"""Cookie-free device claim only; no user-nominated authentication or bytes."""
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from .agent_runtime import AgentClaimRuntime


@method_decorator(csrf_exempt, name="dispatch")
class AgentClaimView(DirectoryPolicyView):
    runtime = None
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
            if self.operation not in {"challenge", "claim"}:
                raise invalid("Agent operation is unavailable")
            if not isinstance(self.runtime, AgentClaimRuntime):
                raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Device claim runtime is unavailable", 503)
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


def agent_claim_routes(*, runtime):
    if not isinstance(runtime, AgentClaimRuntime):
        raise ValueError("actual owned device claim runtime required")
    return [path("v1/agent/" + operation + "/", AgentClaimView.as_view(runtime=runtime,
        operation=operation), name="local-agent-" + operation) for operation in ("challenge", "claim")]
