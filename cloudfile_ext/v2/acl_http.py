"""V2 ACL reads and guarded management. No endpoint enables protected publication."""
from dataclasses import asdict
import logging
import time

import jwt
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication, SessionAuthentication
from seahub.api2.utils import JWT_PRIVATE_KEY

from .acl_policy import PolicyError, Rule, StoredACLError, narrow_to_native
from .acl_runtime import ACLUnavailable, Authority, store
from .acl_store import uuid, RevisionConflict
from .acl_store import validate as validate_acl_rule
from .acl_batch import CONTRACT as LIBRARY_BATCH_CONTRACT, fingerprint, serialize
from .errors import SubjectNotFound
from . import tag_display

logger = logging.getLogger(__name__)


def response(data, status=200):
    value = Response(data, status=status)
    value['Cache-Control'] = 'no-store'
    return value


def failure(error):
    if isinstance(error, SubjectNotFound):
        # "No business subject for this account" is an answer, not an outage.
        # Callers (EAP admin paths) must be able to tell it apart from 503.
        return response({'code': 'SUBJECT_NOT_FOUND'}, 404)
    if isinstance(error, StoredACLError):
        # A stored row that contradicts its own path, hash or column shape is a
        # server-side fault. Answering 400 (INVALID_ACL_REQUEST) blamed the
        # caller and let one legacy path_hash encoding read as an ACL outage.
        logger.error('CloudFile stored ACL inconsistent: %s', error)
        return response({'code': 'ACL_UNAVAILABLE'}, 503)
    if isinstance(error, (ValueError, TypeError, KeyError, PolicyError)):
        return response({'code': 'INVALID_ACL_REQUEST'}, 400)
    if isinstance(error, PermissionError):
        return response({'code': 'ACL_DENIED'}, 403)
    if isinstance(error, RevisionConflict):
        return response({'code': 'ACL_REVISION_CONFLICT'}, 409)
    return response({'code': 'ACL_UNAVAILABLE'}, 503)


def with_tags(repo_id, path, result):
    # Display metadata for the already visible page only. Failure is reported,
    # never shown as "no tags", and never fails the authorized listing.
    items = result['data']
    try:
        tags = tag_display.tags_for_entries(repo_id, path, [(i['path'], i['kind']) for i in items])
        for item in items:
            item['tags'] = tags[(item['path'], item['kind'])]
        result['tags_status'] = 'OK'
    except Exception:
        logger.exception('CloudFile directory tags unavailable')
        for item in items:
            item['tags'] = None
        result['tags_status'] = 'FAILED'


class AuthenticatedACL(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)


class EffectivePermission(AuthenticatedACL):
    def get(self, request):
        try:
            args = request.query_params
            if set(args) - {'repo_id', 'path', 'kind'} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            authority = Authority(request.user.username)
            decision = authority.effective(args['repo_id'], args['path'], args.get('kind', 'dir'))
            if not decision.can_read:
                raise PermissionError('content access denied')
            # Recheck native library qualification after the path-scoped V2
            # decision. Sparse directory rules never classify a whole library;
            # a shared subtree qualifies independently of native membership.
            native = authority.api.check_permission(args['repo_id'], request.user.username)
            if native == 'admin':
                native = 'rw'
            if native not in (None, 'none', 'r', 'rw', 'invisible'):
                raise ACLUnavailable('invalid native content permission')
            decision = narrow_to_native(decision, native)
            if decision is None:
                raise PermissionError('native content access denied')
            return response(dict(**asdict(decision), read=decision.can_read, write=decision.can_write,
                                 visible=decision.visible, protected_publication=False))
        except Exception as error:
            return failure(error)


class SharedDirectories(AuthenticatedACL):
    def get(self, request):
        try:
            if request.query_params:
                raise ValueError()
            return response({'data': Authority(request.user.username).shared_roots(), 'protected_publication': False})
        except Exception as error:
            return failure(error)


def require_repo_manage(user, repo_id):
    """Use CE owner/native repo-admin facts, not global Django IsAdminUser.

    A plain user with repo rw may edit files but cannot silently delegate ACL
    authority to other people. Native repo admins also have rw file access.
    System administrators may repair rules without implicit byte access.
    """
    from seaserv import seafile_api
    from seahub.share.utils import is_repo_admin
    if not getattr(user, 'is_active', False):
        raise PermissionError('inactive native account')
    uuid(repo_id)
    repo = seafile_api.get_repo(repo_id)
    if repo is None or repo.is_virtual:
        raise PermissionError('repository unavailable for ACL management')
    if getattr(user, 'is_staff', False):
        admin = getattr(user, 'admin_permissions', None)
        if admin is not None and admin.can_manage_library():
            return
    if not is_repo_admin(user.username, repo_id):
        raise PermissionError('native repository administrator required')


class DirectoryRules(AuthenticatedACL):
    """CE repository owner/admin or system manager; no global IsAdminUser."""

    def get(self, request):
        try:
            args = request.query_params
            if set(args) != {'repo_id', 'path'} or any(len(args.getlist(k)) != 1 for k in args):
                raise ValueError()
            require_repo_manage(request.user, args['repo_id'])
            # Policy publication needs existence, not content browsing. CE admin
            # directory listing is Pro-only and a machine admin has no implicit
            # read grant. Return only this managed path's existence, no dirents.
            from seaserv import seafile_api
            from .acl_policy import canonical_path
            canonical_path(args['path'])
            exists = bool(seafile_api.get_dir_id_by_path(args['repo_id'], args['path']))
            rows = store().list_path(args['repo_id'], args['path'], getattr(settings, 'CF_ACL_PROVIDER', 'etech'))
            return response({'data': [dict(**asdict(rule), revision=revision) for rule, revision in rows],
                             'directory_exists': exists})
        except Exception as error:
            return failure(error)

    def _write(self, request, *, delete=False):
        try:
            data = request.data
            required = {'repo_id', 'path', 'subject_type', 'namespace', 'external_id',
                        'permission', 'inherit', 'share_mode', 'expected', 'revision'}
            if not isinstance(data, dict) or set(data) != required:
                raise ValueError()
            require_repo_manage(request.user, data['repo_id'])
            if not isinstance(data['inherit'], bool) or not isinstance(data['share_mode'], bool):
                raise ValueError()
            provider = getattr(settings, 'CF_ACL_PROVIDER', 'etech')
            rule = Rule(data['repo_id'], data['path'], provider, data['subject_type'],
                        data['namespace'], data['external_id'], data['permission'],
                        data['inherit'], data['share_mode'])
            committed = store().mutate(rule, expected=data['expected'],
                                       revision=data['revision'], delete=delete)
            return response({'revision': committed, 'repo_id': rule.repo_id, 'path': rule.path})
        except Exception as error:
            return failure(error)

    def post(self, request):
        return self._write(request)

    def put(self, request):
        return self._write(request)

    def delete(self, request):
        return self._write(request, delete=True)

class LibraryACLBatch(AuthenticatedACL):
    """Additive library-level ACL publisher; old directory-rules stays intact.

    Only declared Etech-owned natural keys can be changed. GET reads an
    authoritative complete provider snapshot and PUT checks that fingerprint
    under the same native Branch/transfer-fence ordering as per-rule writes.
    """

    @staticmethod
    def _provider():
        provider = getattr(settings, 'CF_ACL_PROVIDER', 'etech')
        if not isinstance(provider, str) or not provider:
            raise PolicyError('invalid ACL provider')
        return provider

    def get(self, request):
        try:
            args = request.query_params
            if set(args) != {'repo_id'} or len(args.getlist('repo_id')) != 1:
                raise ValueError()
            repo_id = uuid(args['repo_id'])
            require_repo_manage(request.user, repo_id)
            rows = store().provider_snapshot(repo_id, self._provider())
            return response(dict(contract=LIBRARY_BATCH_CONTRACT, repo_id=repo_id,
                                 fingerprint=fingerprint(rows), rules=serialize(rows)))
        except Exception as error:
            return failure(error)

    def post(self, request):
        """Read-only batch preview: one HTTP trip replaces per-directory GETs."""
        try:
            data = request.data
            if (not isinstance(data, dict) or set(data) != {'repo_id', 'paths'}
                    or not isinstance(data['paths'], list)
                    or len(data['paths']) > 4096):
                raise ValueError()
            repo_id = uuid(data['repo_id'])
            require_repo_manage(request.user, repo_id)
            from .acl_policy import canonical_path
            from seaserv import seafile_api
            paths = []
            for item in data['paths']:
                canonical_path(item)
                if item in paths:
                    raise PolicyError('duplicate publication path')
                paths.append(item)
            missing = []
            for path in paths:
                # Native directory existence is not content permission: an EAP
                # administrator may manage ACLs without browsing file bytes.
                if not seafile_api.get_dir_id_by_path(repo_id, path):
                    missing.append(path)
            rows = store().provider_snapshot(repo_id, self._provider())
            return response(dict(contract=LIBRARY_BATCH_CONTRACT, repo_id=repo_id,
                                 fingerprint=fingerprint(rows), rules=serialize(rows),
                                 missing_paths=missing))
        except Exception as error:
            return failure(error)

    def put(self, request):
        try:
            data = request.data
            if (not isinstance(data, dict) or
                    set(data) != {'repo_id', 'expected_fingerprint', 'managed', 'desired'} or
                    not isinstance(data['managed'], list) or
                    not isinstance(data['desired'], list) or
                    len(data['managed']) > 4096 or len(data['desired']) > 4096):
                raise ValueError()
            repo_id = uuid(data['repo_id'])
            require_repo_manage(request.user, repo_id)
            provider = self._provider()
            managed = []
            for item in data['managed']:
                if (not isinstance(item, dict) or
                        set(item) != {'path', 'subject_type', 'namespace', 'external_id'}):
                    raise ValueError()
                key = (item['path'], item['subject_type'], item['namespace'], item['external_id'])
                validate_acl_rule(Rule(repo_id, item['path'], provider, item['subject_type'],
                                       item['namespace'], item['external_id'], 'r', True, False))
                managed.append(key)
            desired = []
            for item in data['desired']:
                if (not isinstance(item, dict) or
                        set(item) != {'path', 'subject_type', 'namespace',
                                      'external_id', 'permission', 'inherit', 'share_mode'} or
                        type(item['inherit']) is not bool or type(item['share_mode']) is not bool):
                    raise ValueError()
                rule = Rule(repo_id, item['path'], provider, item['subject_type'],
                            item['namespace'], item['external_id'], item['permission'],
                            item['inherit'], item['share_mode'])
                validate_acl_rule(rule)
                desired.append(rule)
            applied = store().replace_owned(
                repo_id, provider, expected=data['expected_fingerprint'],
                managed=managed, desired=desired)
            return response(dict(contract=LIBRARY_BATCH_CONTRACT, repo_id=repo_id, **applied))
        except Exception as error:
            return failure(error)


class NativeACLCheck(APIView):
    """Existing native internal JWT, trusted username, bounded exact paths.

    This is a permission check, never a bearer grant. Native code invokes it
    anew at reads and under Branch(master) at final commit.
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)

    def post(self, request):
        try:
            header = request.headers.get('Authorization', '').split()
            if len(header) != 2 or header[0] != 'Token' or not JWT_PRIVATE_KEY:
                raise PermissionError()
            claims = jwt.decode(header[1], JWT_PRIVATE_KEY, algorithms=['HS256'], options={'require': ['exp', 'is_internal']})
            if claims.get('is_internal') is not True or claims['exp'] > time.time() + 310:
                raise PermissionError()
        except Exception:
            return response({'code': 'NATIVE_AUTH_REQUIRED'}, 403)
        try:
            data = request.data
            # Internal listing batch: one trusted call returns one permission
            # per supplied path, with null for hidden entries. Existing atomic
            # read/write checks retain their all-or-deny behaviour.
            partial = data.get('partial') is True
            expected = {'username', 'repo_id', 'checks', 'partial'} if partial else {'username', 'repo_id', 'checks'}
            if set(data) != expected:
                raise ValueError()
            uuid(data['repo_id'])
            if not isinstance(data['username'], str) or not data['username'] or len(data['username']) > 255:
                raise ValueError()
            checks = data['checks']
            if not isinstance(checks, list) or not 1 <= len(checks) <= 4096:
                raise ValueError()
            authority = Authority(data['username'])
            permissions = []
            for check in checks:
                if set(check) != {'path', 'kind', 'action'} or check['action'] not in ('read', 'write'):
                    raise ValueError()
                decision = authority.effective(data['repo_id'], check['path'], check['kind'])
                if not (decision.can_read if check['action'] == 'read' else decision.can_write):
                    if not partial:
                        raise PermissionError()
                    permissions.append(None)
                else:
                    permissions.append(decision.permission)
            # `permissions` is aligned with `checks` and carries the V2 level,
            # not just the batch verdict. Native C asks here for a single path
            # when it has no library grant at all, and it needs to know whether
            # the qualified share root is r or rw: probing again with
            # action=write would double the round trip for every write.
            return response({'allowed': True, 'contract': 'cf-acl-v1',
                             'permissions': permissions})
        except Exception as error:
            return failure(error)


class DirectoryEntries(AuthenticatedACL):
    def get(self, request):
        try:
            args = request.query_params
            if (set(args) - {'repo_id', 'path', 'offset', 'limit', 'with_tags'} or
                    any(len(args.getlist(k)) != 1 for k in args) or args.get('with_tags', 'true') != 'true'):
                raise ValueError()
            result = Authority(request.user.username).entries(args['repo_id'], args['path'],
                offset=int(args.get('offset', '0')), limit=int(args.get('limit', '50')))
            if 'with_tags' in args:
                with_tags(args['repo_id'], args['path'], result)
            return response(result)
        except FileNotFoundError:
            return response({'code': 'DIRECTORY_NOT_FOUND'}, 404)
        except Exception as error:
            return failure(error)
