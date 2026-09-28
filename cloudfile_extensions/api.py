from django.conf import settings
from rest_framework.response import Response

from seahub.api2.base import APIView

from .capabilities import annotation_implementation_registry, management_implementation_registry, audit_query_implementation_registry, build_capability_document


class CapabilitiesView(APIView):
    """Return runtime capabilities without exposing project-specific details."""

    authentication_classes = ()
    permission_classes = ()

    def get(self, request):
        configured = getattr(settings, "CLOUDFILE_CAPABILITIES", {})
        seafile_version = getattr(settings, "SEAFILE_VERSION", "14.0.8")
        webdav_enabled = getattr(settings, "CLOUDFILE_WEBDAV_SERVICE_ENABLED", False)
        from .authorization import gunicorn
        implementations = annotation_implementation_registry(gunicorn._host,
            annotations_enabled=getattr(settings, 'CLOUDFILE_ANNOTATIONS_ENABLED', False),
            oidc_enabled=getattr(settings, 'CLOUDFILE_OIDC_ENABLED', False))
        implementations = management_implementation_registry(implementations, gunicorn._host,
            authorization_enabled=getattr(settings, 'CLOUDFILE_AUTHORIZATION_ENABLED', False),
            oidc_enabled=getattr(settings, 'CLOUDFILE_OIDC_ENABLED', False))
        implementations = audit_query_implementation_registry(implementations, gunicorn._host,
            audit_query_enabled=getattr(settings, 'CLOUDFILE_AUDIT_QUERY_ENABLED', False))
        return Response(build_capability_document(
            configured, seafile_version=seafile_version, webdav_enabled=webdav_enabled,
            implementation_registry=implementations
        ))
