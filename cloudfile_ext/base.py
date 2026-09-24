# -*- coding: utf-8 -*-
"""Framework-level registrations that are not gated by a feature switch."""

from django.urls import path, re_path


def register(registry):
    from cloudfile_ext.views import CloudFileFeaturesView, cloudfile_admin_page
    from cloudfile_ext.upload_resume.apis import UploadTempFileView

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
    ])
