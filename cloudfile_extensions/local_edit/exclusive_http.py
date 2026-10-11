"""Single OIDC/CSRF Web entry for exclusive Checkout and an Agent session.

No browser-visible Checkout token, body-supplied actor, or file-upload bypass.
The real Editing Core acquires the native-managed guard first, then the normal
LocalSessionService validates that guard and stores a short-lived encrypted
handoff. Both use the currently authenticated OIDC actor, never a REST token.
"""
import hashlib
import re
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import resource_ref
from ..editing.service import EditingService
from .session_service import LocalSessionService
from .checkout_credential import deterministic_checkout_token


class ExclusiveStartView(DirectoryPolicyView):
    """Always default-off through the existing post-fork Agent2 feature gate."""
    http_method_names = ["post"]
    operation = "start"

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        lease = None
        try:
            if request.method != "POST" or args or kwargs or not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Native OIDC session required", 401)
            if (request.GET or request.headers.get("Authorization") or
                    request.headers.get("Content-Encoding")):
                raise invalid("No browser authorization bearer or query supported")
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            body = self._body(request)
            fields = ("reference", "device_id", "base_file_id")
            if self.operation == "abandon":
                fields += ("guard_id", "generation", "credential_epoch")
            object_fields(body, fields)
            from .device_proof import _uuid
            _uuid(body["device_id"])
            ref = resource_ref(body["reference"])
            base = body["base_file_id"]
            if ref["kind"] != "file" or not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}", base):
                raise invalid("Current native file baseline required")
            key = request.headers.get("Idempotency-Key")
            if not isinstance(key, str) or not re.fullmatch(r"[\x21-\x7e]{1,128}", key):
                raise ContractError("PRECONDITION_REQUIRED", "Stable idempotency key required", 428)
            from ..authorization.gunicorn import editing_service, local_session_service
            # Fail before acquiring any guard if this particular deployment
            # has not opted in to the Agent2 exclusive feature.
            with local_session_service(request, request_id) as service:
                if not isinstance(service, LocalSessionService) or not service.agent2_exclusive_enabled:
                    raise ContractError("EDIT_UNAVAILABLE", "Exclusive local editing is disabled", 503)
                if self.operation == "start" and service.owner.status(dict(device_id=body["device_id"]))["state"] != "active":
                    raise ContractError("ACCESS_DENIED", "Active paired device required", 403)
            with editing_service(request, request_id) as service:
                if not isinstance(service, EditingService):
                    raise ContractError("EDIT_UNAVAILABLE", "Editing authority unavailable", 503)
                authority = service.resources.write_authority
                token = deterministic_checkout_token(service.resources.store.secret,
                    provider=authority.state.provider, actor=authority.actor,
                    holder=service.holder, reference=ref,
                    device_id=body["device_id"], base_file_id=base, request_key=key)
                if self.operation == "abandon":
                    # Explicit owner action; no silent compensation on failures.
                    # Derive the original proof without disclosing it to Web.
                    result = service.command("abandon", dict(reference=ref,
                        guard_id=body["guard_id"], generation=body["generation"],
                        credential_epoch=body["credential_epoch"], token=token),
                        idempotency_key="exclusive-abandon-" + hashlib.sha256(key.encode("ascii")).hexdigest())
                    response = JsonResponse(result)
                    return self._headers(response, request_id)
                checkout = service.command("checkout", dict(reference=ref,
                    base_file_id=base, token=token), idempotency_key=key)["receipt"]
                if (checkout.get("mode") != "checkout" or checkout.get("base_file_id") != base
                        or checkout.get("guard_id") is None):
                    raise ContractError("EDIT_CONFLICT", "Checkout result changed", 409)
                lease = dict(guard_id=checkout["guard_id"],
                    generation=str(checkout["generation"]),
                    credential_epoch=str(checkout["credential_epoch"]),
                    base_file_id=base, token=token)
            # A failed second step retains the real Checkout. Retrying with
            # the SAME Idempotency-Key reconstructs exactly the same proof;
            # do not silently release a concurrently in-use reservation.
            with local_session_service(request, request_id) as service:
                session = service.create(dict(reference=ref,
                    device_id=body["device_id"], mode="exclusive-edit", lease=lease))
            result = dict(session=session, checkout=dict(
                guard_id=lease["guard_id"], generation=lease["generation"],
                credential_epoch=lease["credential_epoch"], base_file_id=base))
            response = JsonResponse(result, status=201)
        except ContractError as error:
            response = JsonResponse(self._failure(error, request_id, lease), status=error.status)
        except (ValueError, TypeError, UnicodeError):
            response = JsonResponse(invalid("Invalid exclusive Checkout request").response(request_id), status=400)
        except Exception:
            error = ContractError("EDIT_UNAVAILABLE",
                "Exclusive Checkout or session provisioning unavailable; retry the original request key", 503)
            response = JsonResponse(self._failure(error, request_id, lease), status=503)
        return self._headers(response, request_id)

    @staticmethod
    def _failure(error, request_id, lease):
        result = error.response(request_id)
        if lease is not None:
            result["checkout"] = {name: lease[name] for name in
                ("guard_id", "generation", "credential_epoch", "base_file_id")}
            result["retry_original_request"] = True
        return result

    @staticmethod
    def _headers(response, request_id):
        response["Referrer-Policy"] = "no-referrer"
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Vary"] = "Cookie, Authorization"
        response["X-Request-ID"] = request_id
        return response


class ExclusiveAbandonView(ExclusiveStartView):
    """Explicitly release a known Checkout using the original browser request."""
    operation = "abandon"
