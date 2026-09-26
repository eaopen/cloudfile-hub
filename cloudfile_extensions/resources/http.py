"""Read-only resource HTTP adapters; no registration or readiness assertion.

Deployment supplies resource_service as the authenticated owned factory. These
views never expose writes while durable mutation idempotency is unfinished.
"""
import re
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .service import ResourceService


class ResourceResolveView(DirectoryPolicyView):
    service_factory = None
    operation = "resolve"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            expected = "GET" if self.operation == "user_catalog" else "POST"
            if request.method != expected or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Method is not allowed for this resource target", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if self.operation == "user_catalog":
                allowed = {"repo_id", "limit", "after"}
                if (set(request.GET) - allowed or "repo_id" not in request.GET
                        or any(len(request.GET.getlist(key)) != 1 for key in request.GET)
                        or request.read(1)):
                    raise invalid("Invalid tag dictionary query")
                limit = request.GET.get("limit", "50")
                if not re.fullmatch(r"[1-9][0-9]{0,2}", limit) or int(limit) > 100:
                    raise invalid("Invalid tag page size")
                body = dict(repo_id=request.GET["repo_id"], limit=int(limit))
                if "after" in request.GET:
                    body["after"] = request.GET["after"]
            elif self.operation == "resolve":
                if request.GET:
                    raise invalid("Resource resolution takes no query parameters")
                csrf = CsrfViewMiddleware(lambda _: None)
                csrf.process_request(request)
                if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                    raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
                body = self._body(request)
            else:
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource operation is unavailable", 503)
            if not callable(self.service_factory):
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource service is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, ResourceService):
                    raise RuntimeError("invalid resource service assembly")
                result = service.list_user_tag_definitions(body) if self.operation == "user_catalog" else service.resolve(body)
                response = JsonResponse(result)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("RESOURCE_UNAVAILABLE", "Resource service is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


class UserTagCatalogView(ResourceResolveView):
    operation = "user_catalog"
    http_method_names = ["get"]
