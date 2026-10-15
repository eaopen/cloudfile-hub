# -*- coding: utf-8 -*-
"""Single permission-decision facade (permission-tables.md 4.4).

All permission consumers -- web views, REST endpoints, thumbnails, metadata,
search, OnlyOffice, management endpoints -- go through these two entry points.
The decision composes two orthogonal dimensions:

- content: the path-aware native permission (C-side, already narrowed by the
  directory ACL at the seaf-server layer) further narrowed at the Hub;
- manage: library adminship or a covering directory-level admin grant.

This module is a facade, not a re-implementation: the actual decisions live in
cloudfile_ext.acl.service, and check_folder_permission with its 351 call sites
keeps taking exactly the same code path. The facade exists to give the whole
system one named contract -- notably that ``effective_perm`` must always
receive the *path-aware* C result (``seafile_api.check_permission_by_path``),
never the repo-level ``check_permission``, which would drop the C-side
directory-ACL narrowing and could widen access when the Hub and C switches
disagree.
"""

from cloudfile_ext.acl import service


class PermissionService:
    """The one place permission questions get answered."""

    @staticmethod
    def effective_perm(username, repo_id, path, native):
        """Content dimension: pass the path-aware native permission through.

        修改逻辑（2026-10-15 v0.9-only）：不再委托 v0.8 ``apply_dir_acl``——
        统一 schema 下该读取器每次调用都因缺 ``subject`` 列失败，并对**所有**库
        fail-closed（包括普通 CE 库）。目录级裁决由 v0.9 唯一负责：受管库在
        seafile-server 的 scoped 核心与 ``cloudfile_extensions.authorization``
        终判，缺可信上下文的旧入口由 C 层按受管库边界拒绝；非受管库保持原生
        CE 权限。Hub 不再有第二套求解器，也不在此复制 v0.9 的身份解析。

        ``native`` 仍必须来自 ``seafile_api.check_permission_by_path``
        （path-aware）；传库级 ``check_permission`` 会丢掉 C 侧收窄。
        """
        return native

    @staticmethod
    def can_manage(username, repo_id, path):
        """Manage dimension: library admin or covering directory admin.

        仍由 v0.8 服务实现，仅供尚未删除的 legacy 管理视图使用；这些视图已
        不再注册路由，随 v0.8 清理一并退出。
        """
        return service.can_manage(username, repo_id, path)
