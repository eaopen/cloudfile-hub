"""Bounded audit query HTTP adapter; no export or automatic URL registration."""
import re
from uuid import uuid4

from django.http import JsonResponse, HttpResponse
from django.urls import path
from django.views import View
from django.middleware.csrf import CsrfViewMiddleware

from ..common.errors import ContractError, invalid
from .authorized_query import AuthorizedAuditQuery
from ..authorization.http import DirectoryPolicyView


class AuditEventsView(View):
    service_factory = None
    scope = None
    event_class = None
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
            allowed = {"repo_id", "start", "end", "actor_user_id", "resource_uid", "path", "kind", "action", "result", "limit", "cursor"}
            if (set(request.GET) - allowed or not {"repo_id", "start", "end"} <= set(request.GET)
                    or any(len(request.GET.getlist(name)) != 1 for name in request.GET)
                    or request.read(1)):
                raise invalid("Invalid audit query")
            if self.scope == "object":
                if request.GET.get("kind") not in {"file", "dir"} or "path" not in request.GET:
                    raise invalid("Object audit requires path and kind")
            elif self.scope != "library" or "kind" in request.GET or "path" in request.GET:
                raise invalid("Library audit does not accept an object path")
            limit = request.GET.get("limit", "100")
            if not re.fullmatch(r"[1-9][0-9]{0,2}", limit) or int(limit) > 200:
                raise invalid("Invalid audit page size")
            filters = {name: request.GET[name] for name in request.GET if name not in {"limit", "cursor", "kind"}}
            if not callable(self.service_factory):
                raise ContractError("AUDIT_UNAVAILABLE", "Audit service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, AuthorizedAuditQuery):
                    raise RuntimeError("invalid audit service assembly")
                result = service.events(filters, limit=int(limit), cursor=request.GET.get("cursor"),
                                        scope=self.scope, resource_kind=request.GET.get("kind"),
                                        event_class=self.event_class)
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
    # Different URLs make the library-wide management boundary explicit; an
    # ordinary reader must supply a concrete object scope before any scan.
    return [path("v1/events/%s/%s/" % (scope, event_class),
                 AuditEventsView.as_view(service_factory=service_factory,
                                         scope=scope, event_class=event_class),
                 name="audit-%s-%s" % (scope, event_class))
            for scope in ("library", "object")
            for event_class in ("operations", "access", "updates", "permissions")]


class AuditExportView(DirectoryPolicyView):
    service_factory = None
    operation = "create"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            expected = "GET" if self.operation in {"status", "result"} else "POST"
            wanted = set() if self.operation == "create" else {"job_id"}
            if (self.operation not in {"create", "status", "cancel", "result"}
                    or request.method != expected or args or set(kwargs) != wanted):
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed for this export target", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if request.GET:
                raise invalid("Audit export takes no query parameters")
            if expected == "POST":
                csrf = CsrfViewMiddleware(lambda _: None)
                csrf.process_request(request)
                if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                    raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            key = None
            if self.operation == "create":
                key = request.headers.get("Idempotency-Key")
                if key is None:
                    raise ContractError("PRECONDITION_REQUIRED", "Idempotency-Key is required", 428)
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key):
                    raise invalid("Invalid audit export idempotency key")
                body = self._body(request)
            elif request.read(1):
                raise invalid("Audit export target takes no body")
            if not callable(self.service_factory):
                raise ContractError("AUDIT_UNAVAILABLE", "Audit service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, AuthorizedAuditQuery):
                    raise RuntimeError("invalid audit service assembly")
                status = 200
                if self.operation == "create":
                    result, created = service.create_export(body, idempotency_key=key)
                    status = 202 if created else 200
                elif self.operation == "status":
                    result = service.export_status(str(kwargs["job_id"]))
                elif self.operation == "result":
                    result = service.download_export(str(kwargs["job_id"]))
                else:
                    result = service.cancel_export(str(kwargs["job_id"]))
                if self.operation == "result":
                    response = HttpResponse(result, content_type="text/csv; charset=utf-8")
                    response["Content-Disposition"] = 'attachment; filename="audit-export.csv"'
                    response["X-Content-Type-Options"] = "nosniff"
                else:
                    response = JsonResponse(result, status=status)
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


class AuditExportStatusView(AuditExportView):
    operation = "status"
    http_method_names = ["get"]


class AuditExportCancelView(AuditExportView):
    operation = "cancel"


class AuditExportResultView(AuditExportView):
    operation = "result"
    http_method_names = ["get"]


def audit_export_routes(*, service_factory):
    """Explicit job/result routes; no automatic enablement or static files."""
    if not callable(service_factory):
        raise ValueError("trusted owned audit service factory required")
    return [
        path("v1/exports/", AuditExportView.as_view(service_factory=service_factory), name="audit-export-create"),
        path("v1/exports/<uuid:job_id>/", AuditExportStatusView.as_view(service_factory=service_factory), name="audit-export-status"),
        path("v1/exports/<uuid:job_id>/cancel/", AuditExportCancelView.as_view(service_factory=service_factory), name="audit-export-cancel"),
        path("v1/exports/<uuid:job_id>/result/", AuditExportResultView.as_view(service_factory=service_factory), name="audit-export-result"),
    ]
