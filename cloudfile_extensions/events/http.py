"""Bounded audit query HTTP adapter; no export or automatic URL registration."""
import re
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.views import View

from ..common.errors import ContractError, invalid
from .authorized_query import AuthorizedAuditQuery


class AuditEventsView(View):
    service_factory = None
    http_method_names = ["get"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "GET" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed for this audit target", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            query = request.META.get("QUERY_STRING", "")
            if not isinstance(query, str) or len(query.encode("utf-8")) > 16384:
                raise ContractError("REQUEST_TOO_LARGE", "Audit query exceeds the limit", 413)
            allowed = {"repo_id", "start", "end", "actor_user_id", "resource_uid", "path", "action", "result", "limit", "cursor"}
            if (set(request.GET) - allowed or not {"repo_id", "start", "end"} <= set(request.GET)
                    or any(len(request.GET.getlist(name)) != 1 for name in request.GET)
                    or request.read(1)):
                raise invalid("Invalid audit query")
            limit = request.GET.get("limit", "100")
            if not re.fullmatch(r"[1-9][0-9]{0,2}", limit) or int(limit) > 200:
                raise invalid("Invalid audit page size")
            filters = {name: request.GET[name] for name in request.GET if name not in {"limit", "cursor"}}
            if not callable(self.service_factory):
                raise ContractError("AUDIT_UNAVAILABLE", "Audit service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, AuthorizedAuditQuery):
                    raise RuntimeError("invalid audit service assembly")
                result = service.events(filters, limit=int(limit), cursor=request.GET.get("cursor"))
                response = JsonResponse(result)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("AUDIT_UNAVAILABLE", "Audit service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


def audit_query_routes(*, service_factory):
    if not callable(service_factory):
        raise ValueError("trusted owned audit service factory required")
    return [path("v1/events/", AuditEventsView.as_view(service_factory=service_factory), name="audit-events")]
