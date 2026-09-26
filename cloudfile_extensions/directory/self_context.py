"""Actual own-user context diagnostics; never a resource authorization grant."""
from contextlib import contextmanager

from ..authorization.runtime import PolicyServiceFactory, AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier
from ..resources.runtime import expected_subject
from .preparation import SubjectPreparation
from .contexts import SubjectContexts


class OwnContextService:
    def __init__(self, preparation, actor):
        if (not isinstance(preparation, SubjectPreparation)
                or not isinstance(actor, AuthenticatedPolicyActor)
                or preparation.actor != actor.user_id):
            raise ValueError("actual own-subject preparation required")
        self.preparation, self.actor = preparation, actor

    def get(self):
        actor = self.actor.user_id
        state = self.preparation.state
        if state.username(actor) != self.actor.native_username or not state.account_active(actor):
            raise ContractError("ACCESS_DENIED", "Context account is not active or consistent", 403)
        # Normal request trigger: expired context fetches current directory data;
        # this endpoint does not force every browser poll to refresh permissions.
        value = self.preparation.prepare(actor, trigger="request")
        current = self.preparation.contexts.current(actor)
        if (current is None or current["context_epoch"] != value["context_epoch"]
                or state.username(actor) != self.actor.native_username
                or not state.account_active(actor)
                or state.barrier_active(state.provider, actor)):
            raise ContractError("SUBJECT_UNAVAILABLE", "Current context is unavailable", 503)
        # Fixed diagnostic fields only; no email, employee number, attributes,
        # organization/role arrays or authorization rules escape to the caller.
        return SubjectContexts.public_state(current)


class OwnContextFactory(PolicyServiceFactory):
    @contextmanager
    def __call__(self, request, request_id):
        actor = self.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated context identity is required", 401)
        expected_subject(request, actor)
        identifier(request_id)
        with self.preparation_scope(actor.user_id, request_id) as preparation:
            yield OwnContextService(preparation, actor)
