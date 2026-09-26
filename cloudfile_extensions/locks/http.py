"""Unregistered HTTPS/CSRF lease adapters; tokens never appear in URLs."""
import re
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .service import FileLockService


class FileLockView(DirectoryPolicyView):
    service_factory = None
    operation = "status"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Lease operation requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if request.GET:
                raise invalid("Lease operations take no URL parameters")
            if self.operation not in {"status", "acquire", "renew", "release", "force-release"}:
                raise ContractError("LOCK_UNAVAILABLE", "Lease operation is unavailable", 503)
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            body = self._body(request)
            key = request.headers.get("Idempotency-Key")
            if self.operation != "status":
                if key is None:
                    raise ContractError("PRECONDITION_REQUIRED", "Idempotency-Key is required", 428)
                if not re.fullmatch(r"[\x21-\x7e]{1,128}", key):
                    raise invalid("Invalid lease idempotency key")
            if not callable(self.service_factory):
                raise ContractError("LOCK_UNAVAILABLE", "Lease service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, FileLockService):
                    raise RuntimeError("actual authenticated lease service required")
                if self.operation == "status":
                    result = service.status(body)
                elif self.operation == "acquire":
                    result = service.acquire(body, idempotency_key=key)
                elif self.operation == "force-release":
                    result = service.force_release(body, idempotency_key=key)
                else:
                    result = service.change(body, idempotency_key=key, release=self.operation == "release")
                response = JsonResponse(result)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except ValueError:
            error = invalid("Invalid lease request")
            response = JsonResponse(error.response(request_id), status=400)
        except Exception:
            error = ContractError("LOCK_UNAVAILABLE", "Lease service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response
