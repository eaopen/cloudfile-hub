"""Native read-only HTTP adapters; policy writes retain their own authority."""
import re
import stat

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from seahub.api2.authentication import TokenAuthentication

from ..common.errors import ContractError, invalid
from ..resources.paths import resource_ref
from .native_read import response


class NativeEffectiveView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    http_method_names = ('get',)

    def get(self, request):
        def inspect(current):
            if set(request.GET) != {'repo_id', 'path', 'kind'} or any(
                    len(request.GET.getlist(k)) != 1 for k in request.GET):
                raise invalid('Exact resource query required')
            return current.inspect_policy(resource_ref(dict(request.GET.items())))
        return response(request, inspect)



class NativeDirectoryAccessView(APIView):
    """The same directory API under existing authenticated CE sessions.

    v0.9 native OAuth deployments and hosted authorization deployments expose
    exactly the same read-only directory paths and result shapes. No EAP
    endpoint, new login or administrator impersonation is involved.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    http_method_names = ('get',)
    operation = 'resolve'

    def get(self, request):
        from .directory_access import DirectoryAccessService
        from .directory_entries import DirectoryEntriesService

        def read(current):
            params = request.GET
            # Match the hosted directory view: GET bodies are not another way
            # to smuggle an actor, subject or hidden access-mode selector.
            if request._request.read(1):
                raise invalid('Directory queries must not contain a body')
            if any(len(params.getlist(key)) != 1 for key in params):
                raise invalid('Repeated directory query parameter')
            if self.operation == 'shared':
                if set(params) - {'limit', 'after'}:
                    raise invalid('Invalid shared-directory query')
            elif self.operation in ('resolve', 'entries'):
                required = {'repo_id', 'path', 'kind'}
                optional = {'shared_root'} | ({'limit', 'after'} if self.operation == 'entries' else set())
                if not required <= set(params) or set(params) - required - optional:
                    raise invalid('Directory reference required')
            else:
                raise ContractError('POLICY_UNAVAILABLE', 'Unknown native directory operation', 503)

            limit = params.get('limit', '50')
            if self.operation != 'resolve':
                if (not re.fullmatch(r'[1-9][0-9]{0,2}', limit)
                        or int(limit) > 100):
                    raise invalid('Invalid directory page limit')
            if self.operation == 'shared':
                return DirectoryAccessService(current).shared_with_me(
                    limit=int(limit), after=params.get('after'))

            value = {'reference': resource_ref({key: params[key]
                for key in ('repo_id', 'path', 'kind')})}
            if 'shared_root' in params:
                value['shared_root'] = params['shared_root']
            if self.operation == 'resolve':
                return DirectoryAccessService(current).resolve(value)
            return DirectoryEntriesService(current).list(
                value, limit=int(limit), after=params.get('after'))
        return response(request, read)

def directory_page(request, repo_id):
    """CE response shape with native snapshots and current per-entry C decisions.

    Legacy permission RPCs cannot read managed-library policies. Read immutable
    objects only inside ScopedContentReadAuthority's locked transaction instead;
    denied entries never enter the response, including names and metadata.
    """
    def read(current):
        from seaserv import seafile_api
        if (request.GET.get('recursive', '0') != '0'
                or request.GET.get('with_parents', 'false') != 'false'
                or request.GET.get('with_thumbnail', 'false') != 'false'):
            raise invalid('Only bounded single-directory browsing is supported')
        ref = resource_ref(dict(repo_id=repo_id, path=request.GET.get('p', '/'), kind='dir'))
        start, limit = request.GET.get('start', '0'), request.GET.get('limit', '100')
        if not start.isascii() or not start.isdecimal() or not limit.isascii() or not limit.isdecimal():
            raise invalid('Invalid directory page')
        start, limit = int(start), int(limit)
        if start > 2**31 - 502 or not 1 <= limit <= 500:
            raise invalid('Invalid directory page bounds')
        expected = request.GET.get('if_dir_id')
        def consume(cursor, target):
            cursor.execute("SELECT commit_id FROM Branch WHERE repo_id=%s AND name='master' FOR UPDATE", (repo_id,))
            rows = cursor.fetchall()
            if len(rows) != 1 or not re.fullmatch('[0-9a-f]{40}', rows[0][0]):
                raise ContractError('POLICY_UNAVAILABLE', 'Native head unavailable', 503)
            head = rows[0][0]
            dir_id = seafile_api.get_dir_id_by_commit_and_path(repo_id, head, target['path'])
            if dir_id is None:
                raise ContractError('RESOURCE_NOT_FOUND', 'Directory does not exist', 404)
            if expected and expected != dir_id:
                raise ContractError('RESOURCE_VERSION_CONFLICT', 'Directory changed; restart pagination', 409)
            raw = seafile_api.list_dir_by_commit_and_path(repo_id, head, target['path'], start, limit + 1)
            if not isinstance(raw, (list, tuple)) or len(raw) > limit + 1:
                raise ContractError('POLICY_UNAVAILABLE', 'Native page unavailable', 503)
            page = raw[:limit]
            refs, seen = [], set()
            for item in page:
                name, mode = item.obj_name, item.mode
                if (not isinstance(name, str) or name in ('', '.', '..') or '/' in name or '\x00' in name
                        or name in seen or type(mode) is not int or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode))):
                    raise ContractError('POLICY_UNAVAILABLE', 'Invalid native entry', 503)
                seen.add(name)
                refs.append(resource_ref(dict(repo_id=repo_id, path=target['path'].rstrip('/') + '/' + name,
                    kind='dir' if stat.S_ISDIR(mode) else 'file')))
            entries = []
            for offset in range(0, len(refs), 50):
                group = refs[offset:offset + 50]
                rules = current.rules.candidates_many(group, locking=True)
                shares = current.shares.candidates_many(cursor, group, current.subjects())
                if len(rules) != len(group) or len(shares) != len(group):
                    raise ContractError('POLICY_UNAVAILABLE', 'Incomplete page authority', 503)
                for child, acl, shared, item in zip(group, rules, shares, page[offset:offset + 50]):
                    decision = current.core.evaluate_scoped(child, provider=current.state.provider,
                        subject=current.current_subject, rules=acl, ce_permission=current.native_permission,
                        directory_shares=shared, attribute_allowlist=current.preparation.contexts.allowlist,
                        hard_readonly=current.hard_readonly)
                    if not decision['visible'] or not decision['read']:
                        continue
                    if request.GET.get('t') in ('f', 'd') and child['kind'] != {'f': 'file', 'd': 'dir'}[request.GET['t']]:
                        continue
                    entries.append(dict(name=item.obj_name, id=item.obj_id, type=child['kind'],
                        parent_dir=target['path'], permission='rw' if decision['write'] else 'r',
                        size=getattr(item, 'size', 0), mtime=getattr(item, 'mtime', 0),
                        starred=False, is_locked=False))
            # Reuse the shared bounded tag reader only after scoped decisions;
            # hidden entries never participate and no extra HTTP/RPC is needed.
            if request.GET.get('with_display_metadata') == 'true':
                from cloudfile_ext.v2.tag_http import page_tags
                authorized = [(None, target['path'].rstrip('/') + '/' + entry['name'],
                               entry['type'], entry['permission']) for entry in entries]
                for entry, metadata in zip(entries, page_tags(repo_id, authorized)):
                    entry.update(metadata)
            more = len(raw) > limit
            return dict(dirent_list=entries, dir_id=dir_id, head_id=head, acl_enforced=True,
                user_perm='rw' if current.effective_access['write'] else 'r',
                has_more=more, next_start=start + len(page), scanned_count=len(page),
                scan_exhausted=not more)
        return current.consume(ref, consume)
    return response(request, read)


from seahub.api2.endpoints.repos import RepoView


class NativeRepoView(RepoView):
    """Keep CE mutations and the Cookie contract on the current V2 authority."""
    def get(self, request, repo_id):
        from cloudfile_ext.v2.acl_runtime import Authority, ACLUnavailable
        from cloudfile_ext.v2.acl_http import failure, response as v2_response
        from seahub.share.utils import is_repo_admin
        try:
            # The legacy provider selector also starts the retired group sync.
            # Cookie and OIDC sessions must use V2's same UID/org/role projection.
            current = Authority(request.user.username)
            access = current.effective(repo_id, '/')
            if not access.can_read:
                raise PermissionError('Library access denied')
            native = current.api.check_permission_by_path(repo_id, '/', request.user.username)
            if native not in (None, 'r', 'rw', 'invisible'):
                raise ACLUnavailable('Invalid native permission')
            if native not in ('r', 'rw'):
                raise PermissionError('Native library access denied')
            permission = 'rw' if access.can_write and native == 'rw' else 'r'
            repo = current.api.get_repo(repo_id)
            owner = current.api.get_repo_owner(repo_id)
            admin_permissions = getattr(request.user, 'admin_permissions', None)
            global_admin = bool(request.user.is_staff and admin_permissions
                                and admin_permissions.can_manage_library())
            # Management never grants content access. Keep the existing is_admin
            # meaning and expose designated repository administrators separately.
            owner_or_admin = request.user.username == owner or global_admin
            return v2_response(dict(repo_id=repo_id, repo_name=repo.name, name=repo.name,
                permission=permission, user_perm=permission, is_admin=owner_or_admin,
                can_manage=owner_or_admin or bool(is_repo_admin(request.user.username, repo_id)),
                size=repo.size, encrypted=repo.encrypted, is_virtual=repo.is_virtual,
                status=repo.status, repo_type=repo.repo_type, owner_email=owner))
        except Exception as error:
            return failure(error)
