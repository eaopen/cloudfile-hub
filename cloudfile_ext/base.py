# -*- coding: utf-8 -*-
"""Framework-level registrations that are not gated by a feature switch."""

from django.urls import path


def register(registry):
    from cloudfile_ext.views import CloudFileFeaturesView, cloudfile_admin_page

    registry.register_urls([
        path('api/v2.1/cloudfile/features/', CloudFileFeaturesView.as_view(),
             name='cloudfile-features'),
        # The React bundle for this page is registered in
        # frontend/config/webpack.entry.js as `cloudfileAdmin`; without a
        # route and template it was built but unreachable.
        path('cloudfile/admin/', cloudfile_admin_page,
             name='cloudfile-admin-page'),
    ])
