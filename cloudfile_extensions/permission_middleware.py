"""Answer a marked permission-runtime failure with 503, not a false 403.

``seahub.views.check_folder_permission`` denies when the native permission RPC
or the CloudFile policy runtime cannot be read. That denial is byte-identical to
a real "no permission" at the API boundary, so a caller (Etech) showed an
outage as "当前用户无权限". The Hub-side hook only marks the request; the
response shape is decided here, once, so no upstream view has to change and the
permission decision itself stays deny-on-error.

Installed through ``EXTRA_MIDDLEWARE`` in the generated seahub_settings.py, so
it is part of the deployment configuration rather than a new upstream patch.
"""
from uuid import uuid4

from django.http import JsonResponse

from .common.errors import ContractError

PERMISSION_UNAVAILABLE_ATTR = "cf_permission_unavailable"


def mark_permission_unavailable(request):
    """Record that this request could not read the permission runtime.

    Never raises: a request object that refuses the attribute must not turn a
    permission check into a 500.
    """
    try:
        setattr(request, PERMISSION_UNAVAILABLE_ATTR, True)
    except Exception:
        pass


def permission_unavailable(request):
    return getattr(request, PERMISSION_UNAVAILABLE_ATTR, False) is True


class CloudFilePermissionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if permission_unavailable(request) and response.status_code == 403:
            request_id = str(uuid4())
            error = ContractError("POLICY_UNAVAILABLE",
                "CloudFile permission runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
            response["Cache-Control"] = "no-store, max-age=0"
            response["Pragma"] = "no-cache"
            response["Referrer-Policy"] = "no-referrer"
            response["X-Request-ID"] = request_id
        return response
