# -*- coding: utf-8 -*-
"""Operation log backed by the server/seafevents commit-event stream."""


def register(registry):
    from cloudfile_ext.features import is_enabled
    from django.urls import path
    from cloudfile_ext.audit.views import AuditLogView, AuditExportView, audit_page

    if not is_enabled("CF_ENABLE_AUDIT"):
        return
    registry.register_urls([
        path('api/v2.1/cloudfile/audit/', AuditLogView.as_view(),
             name='cloudfile-audit-api'),
        path('api/v2.1/cloudfile/audit/export/', AuditExportView.as_view(),
             name='cloudfile-audit-export'),
        path('cloudfile/audit/', audit_page, name='cloudfile-audit-page'),
    ])
