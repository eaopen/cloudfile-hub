"""Explicit OIDC signed server notification intake, not browser logout."""
from urllib.parse import parse_qsl
from uuid import uuid4

from django.http import HttpResponse, JsonResponse
from django.urls import path
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from ..common.errors import ContractError
from .logout_resources import LogoutResources
from .logout_jobs import BackchannelJobs


@method_decorator(csrf_exempt, name="dispatch")
class BackchannelLogoutView(View):
    resources = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Logout notification requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure notification is required", 401)
            if request.GET or request.META.get("QUERY_STRING"):
                raise ContractError("INVALID_REQUEST", "Notification query is not allowed", 400)
            if request.META.get("HTTP_COOKIE") or request.META.get("HTTP_AUTHORIZATION"):
                raise ContractError("INVALID_REQUEST", "Browser or alternate credentials are not allowed", 400)
            if (request.META.get("CONTENT_TYPE", "").lower() not in {
                    "application/x-www-form-urlencoded",
                    "application/x-www-form-urlencoded; charset=utf-8"}
                    or request.META.get("HTTP_CONTENT_ENCODING")):
                raise ContractError("INVALID_REQUEST", "Notification must be an uncompressed form", 400)
            raw = request.read(65537)
            if not raw or len(raw) > 65536:
                raise ContractError("INVALID_REQUEST", "Notification body is outside the limit", 400)
            try:
                pairs = parse_qsl(raw.decode("ascii"), keep_blank_values=True,
                    strict_parsing=True, encoding="utf-8", errors="strict", max_num_fields=2)
            except (ValueError, UnicodeError):
                raise ContractError("INVALID_REQUEST", "Invalid notification form", 400) from None
            if len(pairs) != 1 or pairs[0][0] != "logout_token" or not pairs[0][1]:
                raise ContractError("INVALID_REQUEST", "Exactly one logout token is required", 400)
            if not isinstance(self.resources, LogoutResources):
                raise ContractError("IDENTITY_UNAVAILABLE", "Notification intake is unavailable", 503)
            with self.resources.intake() as jobs:
                if not isinstance(jobs, BackchannelJobs):
                    raise RuntimeError("invalid notification assembly")
                jobs.submit(pairs[0][1])
            # Protocol acknowledgement only. No job/session/user data or claim
            # that asynchronously deleted sessions have already been terminated.
            response = HttpResponse(status=200)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("IDENTITY_UNAVAILABLE", "Notification intake is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["X-Request-ID"] = request_id
        return response


def backchannel_logout_routes(*, resources):
    if not isinstance(resources, LogoutResources):
        raise ValueError("actual explicitly enabled logout resources required")
    return [path("logout/backchannel/", BackchannelLogoutView.as_view(resources=resources),
        name="cloudfile-oidc-backchannel-logout")]
