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

from .acl_policy import PolicyError, Rule, Decision
from .acl_runtime import ACLUnavailable, Authority, store
from .acl_store import uuid, RevisionConflict
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
            # Match the native upload/read gate for this exact resource. Scope
            # and repository status may narrow C's decision, never widen it;
            # management authority is not a content write permission.
            native = authority.api.check_permission_by_path(args['repo_id'], args['path'], request.user.username)
            if native not in (None, 'r', 'rw', 'invisible'):
                raise ACLUnavailable('invalid native content permission')
            if native not in ('r', 'rw'):
                raise PermissionError('native content access denied')
            if native == 'r' and decision.can_write:
                decision = Decision('r', decision.qualified_root, decision.from_rule)
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
            rows = store().list_path(args['repo_id'], args['path'], getattr(settings, 'CF_ACL_PROVIDER', 'etech'))
            return response({'data': [dict(**asdict(rule), revision=revision) for rule, revision in rows]})
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
            if set(data) != {'username', 'repo_id', 'checks'}:
                raise ValueError()
            uuid(data['repo_id'])
            if not isinstance(data['username'], str) or not data['username'] or len(data['username']) > 255:
                raise ValueError()
            checks = data['checks']
            if not isinstance(checks, list) or not 1 <= len(checks) <= 4096:
                raise ValueError()
            authority = Authority(data['username'])
            for check in checks:
                if set(check) != {'path', 'kind', 'action'} or check['action'] not in ('read', 'write'):
                    raise ValueError()
                decision = authority.effective(data['repo_id'], check['path'], check['kind'])
                if not (decision.can_read if check['action'] == 'read' else decision.can_write):
                    raise PermissionError()
            return response({'allowed': True, 'contract': 'cf-acl-v1'})
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
