"""Unregistered HTTPS/CSRF management of implemented import preparation jobs."""
import re
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .service import MigrationJobService


class MigrationJobView(DirectoryPolicyView):
    service_factory = None
    operation = "status"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Migration operation requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if request.GET or request.headers.get("Content-Encoding", "identity") != "identity":
                raise invalid("Migration operations take uncompressed JSON without URL parameters")
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            body = self._body(request)
            if self.operation not in {"scan", "stage", "verify-copy", "status", "cancel", "retry"}:
                raise invalid("Migration operation is unavailable")
            key = request.headers.get("Idempotency-Key")
            if self.operation in {"scan", "stage", "verify-copy"}:
                if key is None:
                    raise ContractError("PRECONDITION_REQUIRED", "Idempotency-Key is required", 428)
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key):
                    raise invalid("Invalid migration idempotency key")
            if not callable(self.service_factory):
                raise ContractError("MIGRATION_UNAVAILABLE", "Migration runtime is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, MigrationJobService):
                    raise RuntimeError("actual authenticated migration service required")
                if self.operation == "status":
                    result = service.status(body)
                elif self.operation in {"cancel", "retry"}:
                    result = service.transition(self.operation, body)
                else:
                    result = service.submit(self.operation, body, idempotency_key=key)
                response = JsonResponse(result, status=202 if result.get("created") is True else 200)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, TypeError):
            error = invalid("Invalid migration request")
            response = JsonResponse(error.response(request_id), status=400)
        except Exception:
            error = ContractError("MIGRATION_UNAVAILABLE", "Migration runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response
