"""Explicitly enabled, read-only audit event query route."""

from .http import audit_query_routes
from ..authorization.gunicorn import audit_service


urlpatterns = audit_query_routes(service_factory=audit_service)
