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

    from django.urls import re_path

    from cloudfile_ext.acl.apis import DirACLView, DirACLEffectiveView
    from cloudfile_ext.acl.admin_apis import AdminDirACLView
    from cloudfile_ext.acl.service import apply_dir_acl

    repo_id = r'(?P<repo_id>[-0-9a-f]{36})'

    registry.register_urls([
        re_path(r'^api/v2.1/cloudfile/repos/%s/dir-acl/$' % repo_id,
                DirACLView.as_view(), name='cloudfile-dir-acl'),
        re_path(r'^api/v2.1/cloudfile/repos/%s/dir-acl/effective/$' % repo_id,
                DirACLEffectiveView.as_view(),
                name='cloudfile-dir-acl-effective'),
        re_path(r'^api/v2.1/admin/cloudfile/repos/%s/dir-acl/$' % repo_id,
                AdminDirACLView.as_view(), name='cloudfile-admin-dir-acl'),
    ])

    registry.register_permission_check(apply_dir_acl)

    registry.register_menu({
        'key': 'dir-acl',
        'label': 'Directory permissions',
        'url': '/cloudfile/acl/',
        'feature': 'CF_ENABLE_DIR_ACL',
    })
