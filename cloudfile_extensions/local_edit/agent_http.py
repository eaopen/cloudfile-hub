"""Cookie-free device proof endpoints; no nominated identity or file bytes."""
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .agent_runtime import AgentClaimRuntime
from .read_ticket import AgentReadTicketIssuer


@method_decorator(csrf_exempt, name="dispatch")
class AgentClaimView(DirectoryPolicyView):
    runtime = None
    read_issuer = None
    operation = "claim"
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Device claim requires POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure device claim required", 401)
            if (request.GET or request.META.get("QUERY_STRING") or "Cookie" in request.headers or
                    "Authorization" in request.headers or "Content-Encoding" in request.headers):
                raise invalid("Device claim accepts only proof JSON without cookies, authorization or query")
            value = self._body(request)
            if self.operation not in {"challenge", "claim", "read-challenge", "read-ticket", "renew-challenge", "renew", "cancel-challenge", "cancel"}:
                raise invalid("Agent operation is unavailable")
            if not isinstance(self.runtime, AgentClaimRuntime):
                raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Device claim runtime is unavailable", 503)
            if self.operation in {"read-challenge", "read-ticket", "renew-challenge", "renew"}:
                if (not isinstance(self.read_issuer, AgentReadTicketIssuer) or
                        self.read_issuer.runtime is not self.runtime):
                    raise ContractError("LOCAL_READ_UNAVAILABLE", "Native local read runtime is unavailable", 503)
                method = {"read-challenge": self.runtime.read_challenge, "read-ticket": self.read_issuer.issue,
                    "renew-challenge": self.runtime.renew_challenge, "renew": self.runtime.renew}[self.operation]
            elif self.operation in {"cancel-challenge", "cancel"}:
                method = self.runtime.cancel_challenge if self.operation == "cancel-challenge" else self.runtime.cancel
            else:
                method = self.runtime.challenge if self.operation == "challenge" else self.runtime.claim
            response = JsonResponse(method(value, request_id))
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except (ValueError, TypeError, UnicodeError):
            error = invalid("Invalid device claim request")
            response = JsonResponse(error.response(request_id), status=400)
        except Exception:
            error = ContractError("LOCAL_SESSION_UNAVAILABLE", "Device claim runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["X-Request-ID"] = request_id
        return response


def agent_claim_routes(*, runtime, read_issuer=None):
    if not isinstance(runtime, AgentClaimRuntime):
        raise ValueError("actual owned device claim runtime required")
    if read_issuer is not None and (not isinstance(read_issuer, AgentReadTicketIssuer) or
            read_issuer.runtime is not runtime):
        raise ValueError("actual same-runtime local read issuer required")
    operations = ("challenge", "claim", "cancel-challenge", "cancel") if read_issuer is None else (
        "challenge", "claim", "read-challenge", "read-ticket", "renew-challenge", "renew", "cancel-challenge", "cancel")
    return [path("v1/agent/" + operation + "/", AgentClaimView.as_view(runtime=runtime,
        read_issuer=read_issuer, operation=operation), name="local-agent-" + operation) for operation in operations]
