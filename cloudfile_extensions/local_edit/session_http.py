"""Explicit native-browser session metadata, not a file/Agent bearer endpoint."""
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.urls import path

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .session_runtime import LocalSessionFactory
from .session_service import LocalSessionService


class LocalSessionView(DirectoryPolicyView):
    service_factory = None
    operation = "create"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Local session metadata requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure native browser identity required", 401)
            if request.GET or request.headers.get("Content-Encoding", "identity") != "identity":
                raise invalid("Local session requires uncompressed JSON without query")
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            value = self._body(request)
            if self.operation not in {"create", "claim-challenge", "claim"}:
                raise invalid("Local session operation is unavailable")
            if not isinstance(self.service_factory, LocalSessionFactory):
                raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Local session runtime is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, LocalSessionService):
                    raise RuntimeError("actual local resource service required")
                operations = {"create": service.create, "claim-challenge": service.challenge, "claim": service.claim}
                response = JsonResponse(operations[self.operation](value))
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, TypeError, UnicodeError):
            error = invalid("Invalid local session request")
            response = JsonResponse(error.response(request_id), status=400)
        except Exception:
            error = ContractError("LOCAL_SESSION_UNAVAILABLE", "Local session runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


def local_session_routes(*, service_factory):
    if not isinstance(service_factory, LocalSessionFactory):
        raise ValueError("actual owned local resource factory required")
    return [path("v1/sessions/" + operation + "/", LocalSessionView.as_view(
        service_factory=service_factory, operation=operation), name="local-session-" + operation)
        for operation in ("create", "claim-challenge", "claim")]
