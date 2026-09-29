"""Explicitly enabled, read-only audit event query route."""

from django.conf import settings
from django.urls import path

from .http import audit_query_routes, audit_export_routes
from ..authorization.gunicorn import audit_service


def admin_audit(request, category):
    # Seahub's administrator modules require the native runtime; defer their
    # import so route composition still works before that runtime is present.
    from .admin import CloudFileAdminAuditView
    return CloudFileAdminAuditView.as_view()(request, category=category)


urlpatterns = audit_query_routes(service_factory=audit_service) + [
    path("v1/admin/<str:category>/", admin_audit, name="cloudfile-admin-audit"),
]
if getattr(settings, "CLOUDFILE_AUDIT_EXPORT_ENABLED", False) is True:
    urlpatterns += audit_export_routes(service_factory=audit_service)
