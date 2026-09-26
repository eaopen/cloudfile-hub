"""Unregistered POST search adapter; no implicit capability activation."""
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .query_runtime import GuardedSearchRequest


class ResourceSearchView(DirectoryPolicyView):
    service_factory = None
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Search requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure authentication is required", 401)
            if request.GET:
                raise invalid("Search takes no URL query parameters")
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            body = self._body(request)
            if not callable(self.service_factory):
                raise ContractError("SEARCH_UNAVAILABLE", "Search runtime is unavailable", 503)
            with self.service_factory(request, request_id) as service:
                if not isinstance(service, GuardedSearchRequest):
                    raise RuntimeError("actual guarded search request required")
                with service.response(body) as result:
                    response = JsonResponse(result)
                    if len(response.content) > 1048576:
                        raise ContractError("SEARCH_UNAVAILABLE", "Search response exceeds the limit", 503)
                # Exit assertion failures discard the serialized success body.
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("SEARCH_UNAVAILABLE", "Resource search is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response
