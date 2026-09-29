# -*- coding: utf-8 -*-
"""Framework-level registrations that are not gated by a feature switch."""

from django.urls import path, re_path
from django.conf import settings


def register(registry):
    from cloudfile_ext.views import CloudFileFeaturesView, cloudfile_admin_page
    from cloudfile_ext.upload_resume.apis import UploadTempFileView
    from seahub.api2.endpoints.admin.library_administrator import AdminLibraryAdministratorWithAccess

    repo_id = r'(?P<repo_id>[-0-9a-f]{36})'

    registry.register_urls([
        path('api/v2.1/cloudfile/features/', CloudFileFeaturesView.as_view(),
             name='cloudfile-features'),
        # The React bundle for this page is registered in
        # frontend/config/webpack.entry.js as `cloudfileAdmin`; without a
        # route and template it was built but unreachable.
        path('cloudfile/admin/', cloudfile_admin_page,
             name='cloudfile-admin-page'),
        # Browser resumable-upload cleanup is a baseline correctness fix, not
        # an optional product capability: callers must never restart at zero
        # while an old untruncated temp file is still registered.
        re_path(r'^api/v2.1/cloudfile/repos/%s/upload-temp-file/$' % repo_id,
                UploadTempFileView.as_view(),
                name='cloudfile-upload-temp-file'),
        re_path(r'^api/v2.1/admin/cloudfile/libraries/%s/administrator-with-access/$' % repo_id,
                AdminLibraryAdministratorWithAccess.as_view(),
                name='cloudfile-admin-library-administrator-with-access'),
    ])

    # Identity provisioning belongs to the configured OAuth login provider;
    # it is independent of optional directory/group synchronization.
    if getattr(settings, 'ENABLE_OAUTH', False) or getattr(settings, 'ENABLE_CUSTOM_OAUTH', False):
        from cloudfile_ext.identity_api import AdminExternalIdentityView
        registry.register_urls([
            path('api/v2.1/admin/cloudfile/sso/identities/resolve/',
                 AdminExternalIdentityView.as_view(),
                 name='cloudfile-admin-external-identity'),
        ])
