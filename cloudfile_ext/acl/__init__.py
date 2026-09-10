# -*- coding: utf-8 -*-
"""Directory-level ACL.

The Hub half of the control described in cloudfile-docker/docs/
acl-semantics.md. Hiding buttons is not the boundary: the same rules are
enforced in seafile-server so that WebDAV and the desktop sync client cannot
bypass them.
"""


def register(registry):
    # Imported inside register() rather than at module scope so that
    # cloudfile_ext.acl.resolver stays importable without Django -- the shared
    # case set in acl-cases.json is run against it directly.
    from cloudfile_ext.features import is_enabled

    if not is_enabled('CF_ENABLE_DIR_ACL'):
        return

    from django.urls import path, re_path

    from cloudfile_ext.acl import sources
    from cloudfile_ext.acl.apis import (
        DirACLView, DirACLEffectiveView, DirAdminView)
    from cloudfile_ext.acl.admin_apis import (
        AdminDirACLView, AdminDirACLMigrateView, AdminDirAdminView)
    from cloudfile_ext.permissions import PermissionService
    from cloudfile_ext.acl.views import acl_page

    # Where rules come from is pluggable; where they are enforced from is not.
    # See cloudfile_ext/acl/sources.py.
    sources.register(registry)

    repo_id = r'(?P<repo_id>[-0-9a-f]{36})'

    registry.register_urls([
        re_path(r'^api/v2.1/cloudfile/repos/%s/dir-acl/$' % repo_id,
                DirACLView.as_view(), name='cloudfile-dir-acl'),
        re_path(r'^api/v2.1/cloudfile/repos/%s/dir-acl/effective/$' % repo_id,
                DirACLEffectiveView.as_view(),
                name='cloudfile-dir-acl-effective'),
        re_path(r'^api/v2.1/cloudfile/repos/%s/dir-admin/$' % repo_id,
                DirAdminView.as_view(), name='cloudfile-dir-admin'),
        re_path(r'^api/v2.1/admin/cloudfile/repos/%s/dir-acl/$' % repo_id,
                AdminDirACLView.as_view(), name='cloudfile-admin-dir-acl'),
        re_path(r'^api/v2.1/admin/cloudfile/repos/%s/dir-acl/migrate/$' % repo_id,
                AdminDirACLMigrateView.as_view(),
                name='cloudfile-admin-dir-acl-migrate'),
        re_path(r'^api/v2.1/admin/cloudfile/repos/%s/dir-admin/$' % repo_id,
                AdminDirAdminView.as_view(), name='cloudfile-admin-dir-admin'),
        path('cloudfile/acl/', acl_page, name='cloudfile-dir-acl-page'),
    ])

    registry.register_permission_check(PermissionService.effective_perm)

    # 修改逻辑/原因（2026-09-12 规则随目录迁移）：cf_dir_acl / cf_dir_admin 以 path 定位，
    # 而改名/移动不会自动搬运规则——目录改名后规则会留在旧路径上静默失配。
    # 这里注册一个周期任务，按 seafevents 的 Activity（rename/move，带 old_path）
    # 把受影响规则重写到新路径；与搜索索引同一事件源、同一 best-effort 模型，
    # 覆盖所有客户端（改名/移动最终都是一次提交）。
    from cloudfile_ext.acl.migration import migration_tick
    registry.register_periodic_task('acl-path-migration', _migration_interval(),
                                    migration_tick)

    registry.register_menu({
        'key': 'dir-acl',
        'label': 'Directory permissions',
        'url': '/cloudfile/acl/',
        'feature': 'CF_ENABLE_DIR_ACL',
    })

    # Pull from the selected rule source on a schedule. A no-op for local-db,
    # which is why cf-worker stays out of the default compose services until
    # something actually needs it.
    def sync_rules():
        return sources.active(registry).sync()

    registry.register_periodic_task('acl-rule-sync', 300, sync_rules)

def _migration_interval():
    """How often cf-worker scans for moves, in seconds (default 60)."""
    import logging

    from django.conf import settings

    logger = logging.getLogger(__name__)
    try:
        return max(15, int(getattr(settings, 'CF_ACL_MIGRATION_INTERVAL', 60)))
    except (TypeError, ValueError):
        logger.warning('CF_ACL_MIGRATION_INTERVAL is not a number; using 60s')
        return 60
