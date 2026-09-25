from django.conf import settings
from rest_framework.response import Response

from seahub.api2.base import APIView

from .capabilities import build_capability_document


class CapabilitiesView(APIView):
    """Return runtime capabilities without exposing project-specific details."""

    authentication_classes = ()
    permission_classes = ()

    def get(self, request):
        configured = getattr(settings, "CLOUDFILE_CAPABILITIES", {})
        seafile_version = getattr(settings, "SEAFILE_VERSION", "14.0.8")
        return Response(build_capability_document(configured, seafile_version=seafile_version))
