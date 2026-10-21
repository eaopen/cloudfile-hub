"""Owned native-session administrator refresh scopes; no machine auth grant."""
from contextlib import contextmanager

from ..authorization.runtime import PolicyServiceFactory, AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier
from ..resources.runtime import expected_subject
from .preparation import SubjectPreparation
from .refresh_management import UserRefreshManagement


class UserRefreshFactory(PolicyServiceFactory):
    @contextmanager
    def __call__(self, request, request_id):
        actor = self.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated refresh identity is required", 401)
        expected_subject(request, actor)
        identifier(request_id)
        with self.preparation_scope(actor.user_id, request_id) as preparation:
            if not isinstance(preparation, SubjectPreparation) or preparation.actor != actor.user_id:
                raise ContractError("SUBJECT_UNAVAILABLE", "Refresh runtime identity is unavailable", 503)
            state = preparation.state
            yield UserRefreshManagement(state.connection, actor=actor, provider=state.provider,
                native_schema=state.native_schema, identity_schema=state.identity_schema)
