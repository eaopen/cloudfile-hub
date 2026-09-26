"""Unregistered pending-status HTTP adapter; not a session or file endpoint."""
from uuid import UUID, uuid4
import re

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.views import View

from ..common.errors import ContractError
from .pending import PendingLoginStatus, PendingLoginProofs


class PendingStatusView(View):
    service_factory = None  # Trusted request-scoped context manager, never input.
    binding_cookie = "__Host-cloudfile-login-binding"
    http_method_names = ["get", "post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method not in {"GET", "POST"}:
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure pending login is required", 401)
            if request.GET:
                raise ContractError("INVALID_REQUEST", "Pending proof must not be sent in a URL", 400)
            header = request.headers.get("Authorization", "")
            if not header.startswith("CloudFilePending "):
                raise ContractError("AUTHENTICATION_REQUIRED", "Pending proof is required", 401)
            token = header[len("CloudFilePending "):]
            binding = request.COOKIES.get(self.binding_cookie, "")
            PendingLoginProofs._binding(binding)
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
                raise ContractError("AUTHENTICATION_REQUIRED", "Pending proof is invalid", 401)
            if request.method == "POST":
                csrf = CsrfViewMiddleware(lambda _: None)
                csrf.process_request(request)
                if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                    raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
                if request.body:
                    raise ContractError("INVALID_REQUEST", "Pending revoke takes no body", 400)
            if not callable(self.service_factory):
                raise ContractError("IDENTITY_UNAVAILABLE", "Pending status service is unavailable", 503)
            with self.service_factory(request_id) as service:
                if not isinstance(service, PendingLoginStatus):
                    raise RuntimeError("invalid pending service assembly")
                if request.method == "POST":
                    service.proofs.read(token, binding)
                    service.proofs.revoke(token)
                    response = JsonResponse({"revoked": True})
                else:
                    value = service.status(token, binding)
                    if (set(value) != {"job_id", "status", "retryable"} or
                            str(UUID(value["job_id"])) != value["job_id"] or
                            value["status"] not in {"queued", "running", "failed", "cancelled", "succeeded"} or
                            type(value["retryable"]) is not bool):
                        raise RuntimeError("invalid pending status result")
                    response = JsonResponse(value)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("IDENTITY_UNAVAILABLE", "Pending status service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response
