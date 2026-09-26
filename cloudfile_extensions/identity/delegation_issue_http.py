"""Restricted login-service issuance, not a browser impersonation endpoint."""
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields, identifier
from ..resources.paths import resource_ref
from .delegation_issue import UserDelegationIssueFactory


@method_decorator(csrf_exempt, name="dispatch")
class UserDelegationIssueView(DirectoryPolicyView):
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Delegation issuance requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure login-service authentication is required", 401)
            if (request.GET or request.META.get("QUERY_STRING")
                    or "Cookie" in request.headers or "Content-Encoding" in request.headers):
                raise invalid("Login-service issuance takes no query, cookies or compression")
            if not request.headers.get("Authorization", "").startswith("Bearer "):
                raise ContractError("AUTHENTICATION_REQUIRED", "Login-service Bearer is required", 401)
            body = self._body(request)
            object_fields(body, ("userId", "reference"), ("operation",))
            identifier(body["userId"], maximum=225)
            reference = resource_ref(body["reference"])
            operation = body.get("operation", "download")
            if reference["kind"] != "file" or operation not in ("view", "download"):
                raise invalid("Delegation requires one exact file read action")
            if not isinstance(self.service_factory, UserDelegationIssueFactory):
                raise ContractError("POLICY_UNAVAILABLE", "Delegation issuance runtime is unavailable", 503)
            with self.service_factory(request, request_id, body["userId"]) as issuer:
                result = issuer.issue(request, reference, operation=operation)
            response = JsonResponse(result, status=201)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("POLICY_UNAVAILABLE", "Delegation issuance runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Authorization"
        response["X-Request-ID"] = request_id
        return response


def delegation_issue_routes(*, factory):
    if not isinstance(factory, UserDelegationIssueFactory):
        raise ValueError("actual trusted login-service issuance factory required")
    return [path("delegations/", UserDelegationIssueView.as_view(service_factory=factory),
        name="cloudfile-user-delegation-issue")]
