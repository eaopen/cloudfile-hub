"""Owned delegated file ticket issuance; no route or capability enablement."""
from contextlib import contextmanager
import json
import math
from uuid import UUID

from ..authorization.resources import PolicyResources
from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from ..resources.paths import resource_ref
from .ticket_transport import resolve_and_issue_native_ticket
from .user_delegation import UserDelegationVerifier


class DelegatedReadTicketIssuer:
    def __init__(self, preparation, verifier):
        if (not isinstance(preparation, SubjectPreparation)
                or not isinstance(verifier, UserDelegationVerifier)):
            raise ValueError("actual preparation and delegation verifier required")
        self.preparation, self.verifier = preparation, verifier

    def issue(self, request, reference, *, operation="download"):
        if (not request.is_secure() or "Cookie" in request.headers
                or request.GET):
            raise ContractError("AUTHENTICATION_REQUIRED", "Secure cookie-free delegation is required", 401)
        principal = self.verifier.verify(request.headers.get("Authorization"))
        ref = resource_ref(reference)
        principal.require(ref, operation)
        state = self.preparation.state
        if principal.user_id != self.preparation.actor or principal.provider != state.provider:
            raise ContractError("ACCESS_DENIED", "Delegation subject is not allowed", 403)
        self.preparation.prepare(principal.user_id)
        current = self.preparation.contexts.current(principal.user_id)
        if current is None or current["context_epoch"] != principal.epoch:
            raise ContractError("AUTHENTICATION_REQUIRED", "Delegation permission version changed", 401)
        self.verifier.assert_active(principal)
        username = state.username(principal.user_id)
        conditions = dict(path=ref["path"],
            context=dict(provider=state.provider, userId=principal.user_id, epoch=principal.epoch),
            scopes=[dict(type="provider", provider=state.provider, external_id=state.provider),
                dict(type="user", provider=state.provider, external_id=principal.user_id),
                dict(type="repo", provider="cloudfile", external_id=ref["repo_id"])],
            user_delegation=dict(service_id=principal.service_id, token_id=principal.token_id,
                issued_at=principal.issued_at, expires_at=principal.expires_at))
        encoded = json.dumps(conditions, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 16384:
            raise ContractError("INVALID_REQUEST", "Native ticket conditions exceed budget", 400)
        try:
            ticket = resolve_and_issue_native_ticket(ref["repo_id"], ref["path"], operation, username, encoded)
            if not isinstance(ticket, str) or str(UUID(ticket)) != ticket:
                raise ValueError("invalid native ticket response")
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Native delegated ticket is unavailable", 503) from None
        self.verifier.assert_active(principal)
        current = self.preparation.contexts.current(principal.user_id)
        if current is None or current["context_epoch"] != principal.epoch:
            raise ContractError("AUTHENTICATION_REQUIRED", "Delegation permission version changed", 401)
        remaining = math.floor(principal.expires_at - self.verifier.clock())
        if remaining < 1:
            raise ContractError("AUTHENTICATION_REQUIRED", "Delegation expired", 401)
        return dict(ticket=ticket, expires_in=min(60, remaining))


class DelegatedReadTicketFactory:
    def __init__(self, *, resources, verifier):
        if (not isinstance(resources, PolicyResources)
                or not isinstance(verifier, UserDelegationVerifier)
                or verifier.revocations.redis is not resources.redis):
            raise ValueError("owned policy and same actual Redis revocation resources required")
        self.resources, self.verifier = resources, verifier

    @contextmanager
    def __call__(self, request, request_id):
        if not request.is_secure() or "Cookie" in request.headers or request.GET:
            raise ContractError("AUTHENTICATION_REQUIRED", "Secure cookie-free delegation is required", 401)
        principal = self.verifier.verify(request.headers.get("Authorization"))
        if principal.provider != self.resources.provider:
            raise ContractError("ACCESS_DENIED", "Delegation provider is not allowed", 403)
        with self.resources.preparation(principal.user_id, request_id) as preparation:
            yield DelegatedReadTicketIssuer(preparation, self.verifier)
