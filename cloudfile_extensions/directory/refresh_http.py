"""Explicit native-session administrator refresh HTTP, not machine delegation."""
import re
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.urls import path
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .refresh_management import UserRefreshManagement


class UserRefreshView(DirectoryPolicyView):
    service_factory = None
    operation = "submit"
    authentication_mode = "session"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            expected = "GET" if self.operation == "status" else "POST"
            wanted = set() if self.operation == "submit" else {"job_id"}
            if (self.operation not in {"submit", "status", "retry", "cancel"} or request.method != expected
                    or args or set(kwargs) != wanted):
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed for this refresh target", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if request.GET:
                raise invalid("Refresh target takes no query parameters")
            if self.authentication_mode not in {"session", "service"}:
                raise RuntimeError("invalid fixed refresh authentication mode")
            if self.authentication_mode == "service" and request.headers.get("Cookie"):
                raise invalid("Machine refresh does not accept browser cookies")
            if self.authentication_mode == "service" and not request.headers.get("Authorization", "").startswith("Bearer "):
                raise ContractError("AUTHENTICATION_REQUIRED", "Machine Bearer authentication is required", 401)
            if self.operation in {"submit", "retry", "cancel"}:
                if self.authentication_mode == "session":
                    csrf = CsrfViewMiddleware(lambda _: None)
                    csrf.process_request(request)
                    if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                        raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            if self.operation == "submit":
                key = request.headers.get("Idempotency-Key")
                if key is None:
                    raise ContractError("PRECONDITION_REQUIRED", "Idempotency-Key is required", 428)
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key):
                    raise invalid("Invalid refresh idempotency key")
                body = self._body(request)
            elif request.read(1):
                raise invalid("Refresh status and retry take no body")
            if self.operation in {"retry", "cancel"}:
                condition = request.headers.get("If-Match")
                if condition is None:
                    raise ContractError("PRECONDITION_REQUIRED", "If-Match is required", 428)
                match = re.fullmatch(r'"cf-refresh:' + re.escape(str(kwargs["job_id"])) + r':(0|[1-9][0-9]{0,18})"', condition)
                if match is None or int(match[1]) > 2 ** 63 - 1:
                    raise invalid("Invalid refresh attempt condition")
            if not callable(self.service_factory):
                raise ContractError("SUBJECT_UNAVAILABLE", "Refresh service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, UserRefreshManagement):
                    raise RuntimeError("invalid refresh management assembly")
                if service.machine != (self.authentication_mode == "service"):
                    raise RuntimeError("refresh authentication assembly mismatch")
                status = 200
                if self.operation == "submit":
                    job_id, created = service.submit(body, idempotency_key=key)
                    # Status performs fresh management authorization. A lost
                    # response does not cancel the accepted durable job; retry
                    # must use the same idempotency key and request.
                    result, etag = service.status(job_id, with_condition=True)
                    status = 202 if created else 200
                elif self.operation in {"retry", "cancel"}:
                    transition = service.cancel if self.operation == "cancel" else service.retry_failed
                    result, etag = transition(str(kwargs["job_id"]),
                        expected_attempt=int(match[1]), with_condition=True)
                else:
                    result, etag = service.status(str(kwargs["job_id"]), with_condition=True)
                response = JsonResponse(result, status=status)
                response["ETag"] = etag
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("SUBJECT_UNAVAILABLE", "Refresh service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


class UserRefreshStatusView(UserRefreshView):
    operation = "status"
    http_method_names = ["get"]


class UserRefreshRetryView(UserRefreshView):
    operation = "retry"


class UserRefreshCancelView(UserRefreshView):
    operation = "cancel"


def user_refresh_routes(*, service_factory):
    if not callable(service_factory):
        raise ValueError("trusted owned native-session refresh factory required")
    return [
        path("v1/refreshes/", UserRefreshView.as_view(service_factory=service_factory), name="cloudfile-user-refresh-submit"),
        path("v1/refreshes/<uuid:job_id>/", UserRefreshStatusView.as_view(service_factory=service_factory), name="cloudfile-user-refresh-status"),
        path("v1/refreshes/<uuid:job_id>/retry/", UserRefreshRetryView.as_view(service_factory=service_factory), name="cloudfile-user-refresh-retry"),
        path("v1/refreshes/<uuid:job_id>/cancel/", UserRefreshCancelView.as_view(service_factory=service_factory), name="cloudfile-user-refresh-cancel"),
    ]


@method_decorator(csrf_exempt, name="dispatch")
class MachineUserRefreshView(UserRefreshView):
    authentication_mode = "service"


class MachineUserRefreshStatusView(MachineUserRefreshView):
    operation = "status"
    http_method_names = ["get"]


class MachineUserRefreshRetryView(MachineUserRefreshView):
    operation = "retry"


class MachineUserRefreshCancelView(MachineUserRefreshView):
    operation = "cancel"


def machine_user_refresh_routes(*, service_factory):
    """Mount instead of session routes at this scope, never fallback to Cookie."""
    if not callable(service_factory):
        raise ValueError("trusted owned machine refresh factory required")
    return [
        path("v1/refreshes/", MachineUserRefreshView.as_view(service_factory=service_factory), name="cloudfile-machine-refresh-submit"),
        path("v1/refreshes/<uuid:job_id>/", MachineUserRefreshStatusView.as_view(service_factory=service_factory), name="cloudfile-machine-refresh-status"),
        path("v1/refreshes/<uuid:job_id>/retry/", MachineUserRefreshRetryView.as_view(service_factory=service_factory), name="cloudfile-machine-refresh-retry"),
        path("v1/refreshes/<uuid:job_id>/cancel/", MachineUserRefreshCancelView.as_view(service_factory=service_factory), name="cloudfile-machine-refresh-cancel"),
    ]
