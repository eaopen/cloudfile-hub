"""Explicit contexts/me route; no force refresh or automatic enablement."""
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.views import View

from ..common.errors import ContractError, invalid
from .self_context import OwnContextService


class OwnContextView(View):
    service_factory = None
    http_method_names = ["get"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "GET" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed for this context target", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if request.GET or request.read(1):
                raise invalid("Own context takes no parameters or body")
            if not callable(self.service_factory):
                raise ContractError("SUBJECT_UNAVAILABLE", "Context service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, OwnContextService):
                    raise RuntimeError("invalid own-context assembly")
                response = JsonResponse(service.get())
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("SUBJECT_UNAVAILABLE", "Context service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


def own_context_routes(*, service_factory):
    if not callable(service_factory):
        raise ValueError("trusted owned context service factory required")
    return [path("v1/contexts/me/", OwnContextView.as_view(service_factory=service_factory), name="cloudfile-own-context")]
