"""Cookie-free device proof endpoints; no nominated identity or file bytes."""
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from ..authorization.http import DirectoryPolicyView
from .private_http import transport_allowed
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
            if not transport_allowed(request):
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure device claim required", 401)
            if (request.GET or request.META.get("QUERY_STRING") or "Cookie" in request.headers or
                    "Authorization" in request.headers or "Content-Encoding" in request.headers):
                raise invalid("Device claim accepts only proof JSON without cookies, authorization or query")
            value = self._body(request)
            if self.operation not in {"challenge", "claim", "read-challenge", "read-ticket", "renew-challenge", "renew", "cancel-challenge", "cancel", "commit-challenge", "commit-authorize", "commit-upload-authorize", "commit-status-challenge", "commit-status", "lease-challenge", "lease-receive", "lease-confirm-challenge", "lease-confirm", "lease-renew-challenge", "lease-renew", "lease-abandon-challenge", "lease-abandon", "optimistic-upload-challenge", "optimistic-upload-authorize", "optimistic-status-challenge", "optimistic-status"}:
                raise invalid("Agent operation is unavailable")
            if not isinstance(self.runtime, AgentClaimRuntime):
                raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Device claim runtime is unavailable", 503)
            if self.operation in {"read-challenge", "read-ticket", "renew-challenge", "renew"}:
                if (not isinstance(self.read_issuer, AgentReadTicketIssuer) or
                        self.read_issuer.runtime is not self.runtime):
                    raise ContractError("LOCAL_READ_UNAVAILABLE", "Native local read runtime is unavailable", 503)
                method = {"read-challenge": self.runtime.read_challenge, "read-ticket": self.read_issuer.issue,
                    "renew-challenge": self.runtime.renew_challenge, "renew": self.runtime.renew}[self.operation]
            elif self.operation in {"commit-challenge", "commit-authorize", "commit-upload-authorize", "commit-status-challenge", "commit-status", "lease-challenge", "lease-receive", "lease-confirm-challenge", "lease-confirm", "lease-renew-challenge", "lease-renew", "lease-abandon-challenge", "lease-abandon", "optimistic-upload-challenge", "optimistic-upload-authorize", "optimistic-status-challenge", "optimistic-status"}:
                method = getattr(self.runtime, self.operation.replace("-", "_"))
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
        "challenge", "claim", "read-challenge", "read-ticket", "renew-challenge", "renew", "cancel-challenge", "cancel", "commit-challenge", "commit-authorize", "commit-upload-authorize", "commit-status-challenge", "commit-status", "lease-challenge", "lease-receive", "lease-confirm-challenge", "lease-confirm", "lease-renew-challenge", "lease-renew", "lease-abandon-challenge", "lease-abandon", "optimistic-upload-challenge", "optimistic-upload-authorize", "optimistic-status-challenge", "optimistic-status")
    from .upload_http import AgentUploadView
    from .optimistic_upload_http import AgentOptimisticUploadView
    from .block_http import AgentBlockView
    block = [path("v1/agent/commit-block-" + operation + "/", AgentBlockView.as_view(
        runtime=runtime, operation=operation), name="local-agent-commit-block-" + operation)
        for operation in ("plan", "stage", "publish")] if read_issuer is not None else []
    optimistic_blocks = [path("v1/agent/optimistic-block-" + operation + "/",
        AgentBlockView.as_view(runtime=runtime, operation=operation, optimistic=True),
        name="local-agent-optimistic-block-" + operation)
        for operation in ("plan", "stage", "publish")] if read_issuer is not None else []
    upload = [path("v1/agent/commit-upload/", AgentUploadView.as_view(runtime=runtime),
        name="local-agent-commit-upload")] if read_issuer is not None else []
    optimistic = [path("v1/agent/optimistic-upload/",
        AgentOptimisticUploadView.as_view(runtime=runtime),
        name="local-agent-optimistic-upload")] if read_issuer is not None else []
    return upload + block + optimistic_blocks + optimistic + [path("v1/agent/" + operation + "/", AgentClaimView.as_view(runtime=runtime,
        read_issuer=read_issuer, operation=operation), name="local-agent-" + operation) for operation in operations]
