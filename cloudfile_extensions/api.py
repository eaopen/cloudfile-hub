from django.conf import settings
from rest_framework.response import Response

from seahub.api2.base import APIView

from .capabilities import administrator_policy_implementation_registry, library_share_implementation_registry, annotation_implementation_registry, management_implementation_registry, legacy_implementation_registry, audit_query_implementation_registry, local_edit_implementation_registry, build_capability_document


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
        # The legacy managed-share API is still live on legacy SSO deployments;
        # the v0.8 directory-ACL runtime is retired and no longer advertised.
        implementations = legacy_implementation_registry(implementations,
            authorization_enabled=getattr(settings, 'CLOUDFILE_AUTHORIZATION_ENABLED', False),
            sso_enabled=getattr(settings, 'CF_ENABLE_SSO', False))
        implementations = library_share_implementation_registry(implementations, gunicorn._host,
            sso_enabled=getattr(settings, 'CF_ENABLE_SSO', False))
        implementations = audit_query_implementation_registry(implementations, gunicorn._host,
            audit_query_enabled=getattr(settings, 'CLOUDFILE_AUDIT_QUERY_ENABLED', False))
        implementations = local_edit_implementation_registry(implementations, gunicorn._host,
            local_edit_enabled=getattr(settings, 'CLOUDFILE_LOCAL_EDIT_ENABLED', False),
            oidc_enabled=getattr(settings, 'CLOUDFILE_OIDC_ENABLED', False))
        from .authorization.admin_management import native_administrator_ready
        implementations = administrator_policy_implementation_registry(implementations, gunicorn._host,
            enabled=getattr(settings, 'CLOUDFILE_ADMIN_POLICY_ENABLED', not getattr(settings, 'CLOUDFILE_AUTHORIZATION_ENABLED', False)),
            native_ready=native_administrator_ready)
        from .authorization.native_read import ready
        from .capabilities import native_read_implementation_registry
        implementations = native_read_implementation_registry(implementations, ready=ready)
        return Response(build_capability_document(
            configured, seafile_version=seafile_version, webdav_enabled=webdav_enabled,
            implementation_registry=implementations
        ))
