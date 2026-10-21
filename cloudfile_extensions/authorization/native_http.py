"""Current V2-authorized native repository metadata route.

The former Resource/DirectoryService/PolicyHost implementation was retired.
No SQL table outside the reviewed CloudFile 4+1 set is consulted here.
"""
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
