"""Native OIDC management adapter for read-only reconciliation, unregistered."""
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.urls import path

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..identity.read_ticket_http import native_download_actor
from ..identity.resources import LoginResources
from ..identity.session_authority import OIDCSessionAuthority
from .authorized_query import AuthorizedAuditQuery
from .read_reconciliation import ReadAuditReconciliation


class ReadReconciliationView(DirectoryPolicyView):
    login_resources = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Reconciliation requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure native session is required", 401)
            if (request.GET or request.META.get("QUERY_STRING") or "Authorization" in request.headers
                    or "Content-Encoding" in request.headers):
                raise invalid("Reconciliation accepts native session JSON only")
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            body = self._body(request)
            object_fields(body, ("repo_id", "start", "end"))
            if not isinstance(self.login_resources, LoginResources) or not callable(self.service_factory):
                raise ContractError("AUDIT_UNAVAILABLE", "Reconciliation runtime is unavailable", 503)
            actor = native_download_actor(request)
            session = OIDCSessionAuthority(self.login_resources)
            session.check(request)
            with self.service_factory(request, request_id) as service:
                if type(service) is not AuthorizedAuditQuery or service.authority.actor != actor.user_id:
                    raise ContractError("AUDIT_UNAVAILABLE", "Reconciliation identity is unavailable", 503)
                result = ReadAuditReconciliation(service).report(body)
                # Actual SQL OIDC/fence guard at response materialization;
                # directory preparation and page I/O do not hold this lock.
                with session.guard(request):
                    response = JsonResponse(result)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("AUDIT_UNAVAILABLE", "Reconciliation runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response


def read_reconciliation_routes(*, service_factory, login_resources):
    if not callable(service_factory) or not isinstance(login_resources, LoginResources):
        raise ValueError("owned native login and audit resources required")
    return [path("v1/read-reconciliation/", ReadReconciliationView.as_view(
        service_factory=service_factory, login_resources=login_resources), name="cloudfile-read-reconciliation")]
