"""Compatibility facade for the one V2 content Authority and CE library management.

This module must not import retired v0.8 acl.service/DirAdmin or synthesize
managed-library classifications. The content result is always calculated for
the authenticated actor and concrete requested directory.
"""

class PermissionService:
    @staticmethod
    def effective_perm(username, repo_id, path, native):
        from cloudfile_ext.v2.acl_runtime import Authority
        try:
            decision = Authority(username).effective(repo_id, path, 'dir')
        except Exception:
            # The legacy facade has no unavailable status channel; never
            # restore a wider, stale native permission on an ACL outage.
            return None
        return decision.permission if decision.can_read else None

    @staticmethod
    def can_manage(username, repo_id, path):
        # Directory contents rw never grants ACL-management authority.
        # CE owner/designated repo-admin facts remain the management source.
        try:
            from seahub.share.utils import is_repo_admin
            return bool(is_repo_admin(username, repo_id))
        except Exception:
            return False
