"""Unregistered policy HTTP views; deployment must authenticate in the factory."""
import json
import re
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.views import View

from ..common.errors import ContractError, invalid
from .service import DirectoryPolicyService


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


class DirectoryPolicyView(View):
    service_factory = None  # context manager (request, request_id), authenticates actor
    domain = "acl"  # fixed trusted URL configuration, never request JSON
    http_method_names = ["get", "post", "put", "delete"]

    def _body(self, request):
        if request.content_type != "application/json":
            raise ContractError("UNSUPPORTED_MEDIA_TYPE", "JSON is required", 415)
        length = request.META.get("CONTENT_LENGTH", "")
        if length and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > 16384):
            raise ContractError("REQUEST_TOO_LARGE", "Policy request exceeds the limit", 413)
        body = request.body
        if len(body) > 16384:
            raise ContractError("REQUEST_TOO_LARGE", "Policy request exceeds the limit", 413)
        try:
            value = json.loads(body.decode("utf-8"), object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError, RecursionError):
            raise invalid("Invalid policy JSON") from None

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method not in {"GET", "POST", "PUT", "DELETE"}:
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            rule_id = kwargs.get("rule_id")
            if ((request.method in {"GET", "POST"} and rule_id is not None) or
                    (request.method in {"PUT", "DELETE"} and rule_id is None)):
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed for this target", 405)
            if request.method == "GET":
                allowed = {"repo_id", "path", "kind", "limit", "after"}
                if set(request.GET) - allowed or any(len(request.GET.getlist(key)) != 1 for key in request.GET):
                    raise invalid("Invalid policy query")
                if not {"repo_id", "path", "kind"} <= set(request.GET) or request.body:
                    raise invalid("Policy target is required")
                limit = request.GET.get("limit", "50")
                if not re.fullmatch(r"[1-9][0-9]{0,2}", limit):
                    raise invalid("Invalid policy page limit")
                body = dict(reference={key: request.GET[key] for key in ("repo_id", "path", "kind")})
            else:
                if request.GET:
                    raise invalid("Policy writes take no query parameters")
                csrf = CsrfViewMiddleware(lambda _: None)
                csrf.process_request(request)
                if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                    raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
                body = self._body(request)
            if not callable(self.service_factory):
                raise ContractError("POLICY_UNAVAILABLE", "Policy service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, DirectoryPolicyService):
                    raise RuntimeError("invalid authenticated policy assembly")
                if request.method == "GET":
                    result = service.list(self.domain, body, limit=int(limit), after=request.GET.get("after"))
                elif request.method == "POST":
                    result = service.create(self.domain, body, idempotency_key=request.headers.get("Idempotency-Key"))
                elif request.method == "PUT":
                    result = service.replace(self.domain, rule_id, body, if_match=request.headers.get("If-Match"),
                        idempotency_key=request.headers.get("Idempotency-Key"))
                else:
                    result = service.delete(self.domain, rule_id, body, if_match=request.headers.get("If-Match"),
                        idempotency_key=request.headers.get("Idempotency-Key"))
                response = JsonResponse(result)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("POLICY_UNAVAILABLE", "Policy service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


class DirectoryAdminView(DirectoryPolicyView):
    domain = "admins"
