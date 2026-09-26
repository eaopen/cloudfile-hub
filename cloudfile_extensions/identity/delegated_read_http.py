"""Cookie-free exact-file delegation adapter; explicitly unregistered."""
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import resource_ref
from .delegated_read_ticket import DelegatedReadTicketFactory


@method_decorator(csrf_exempt, name="dispatch")
class DelegatedReadTicketView(DirectoryPolicyView):
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Delegated tickets require POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure delegation is required", 401)
            if (request.GET or request.META.get("QUERY_STRING")
                    or "Cookie" in request.headers or "Content-Encoding" in request.headers):
                raise invalid("Delegated tickets accept no query, cookies or compression")
            if not request.headers.get("Authorization", "").startswith("Bearer "):
                raise ContractError("AUTHENTICATION_REQUIRED", "User delegation Bearer is required", 401)
            body = self._body(request)
            object_fields(body, ("reference",), ("operation",))
            reference = resource_ref(body["reference"])
            operation = body.get("operation", "download")
            if reference["kind"] != "file" or operation not in ("view", "download"):
                raise invalid("Delegated tickets require a file and supported read action")
            if not isinstance(self.service_factory, DelegatedReadTicketFactory):
                raise ContractError("POLICY_UNAVAILABLE", "Delegated ticket runtime is unavailable", 503)
            with self.service_factory(request, request_id) as issuer:
                result = issuer.issue(request, reference, operation=operation)
            response = JsonResponse(result, status=201)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("POLICY_UNAVAILABLE", "Delegated ticket runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Authorization"
        response["X-Request-ID"] = request_id
        return response


def delegated_read_ticket_routes(*, resources, verifier):
    factory = DelegatedReadTicketFactory(resources=resources, verifier=verifier)
    return [path("delegated-read-tickets/", DelegatedReadTicketView.as_view(service_factory=factory),
        name="cloudfile-delegated-read-ticket")]
