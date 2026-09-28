"""Request-scoped assembly for authenticated host policy adapters.

Authentication and owned SQL/Redis resources are supplied by trusted deployment
hooks. No request header/body can select an actor, provider or policy library.
"""
from contextlib import contextmanager
from dataclasses import dataclass

from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.preparation import SubjectPreparation
from .core import PolicyCore
from .management import DirectoryManagement
from .service import DirectoryPolicyService


@dataclass(frozen=True)
class AuthenticatedPolicyActor:
    user_id: str
    native_username: str

    def __post_init__(self):
        identifier(self.user_id, maximum=225)
        identifier(self.native_username)


class PolicyServiceFactory:
    def __init__(self, *, authenticate, preparation_scope, core, cloud_mode):
        if not callable(authenticate) or not callable(preparation_scope):
            raise ValueError("trusted authentication and owned preparation scope required")
        if not isinstance(core, PolicyCore) or type(cloud_mode) is not bool:
            raise ValueError("fixed native policy core and explicit cloud mode required")
        self.authenticate = authenticate
        self.preparation_scope = preparation_scope
        self.core, self.cloud_mode = core, cloud_mode

    @contextmanager
    def __call__(self, request, request_id):
        # Authenticate before allocating domain resources; never interpret a
        # supplied business ID or contact email as a native session identity.
        actor = self.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated policy identity is required", 401)
        identifier(request_id)
        with self.preparation_scope(actor.user_id, request_id) as preparation:
            if not isinstance(preparation, SubjectPreparation) or preparation.actor != actor.user_id:
                raise ContractError("POLICY_UNAVAILABLE", "Policy runtime identity is unavailable", 503)
            state = preparation.state
            # Prevent accidental assembly for another native account even when
            # the host's business actor is correct. Mutation rechecks binding,
            # native active status and all authority under its own transaction.
            if state.username(actor.user_id) != actor.native_username:
                raise ContractError("ACCESS_DENIED", "Native policy identity does not match", 403)
            if not state.account_active(actor.user_id):
                raise ContractError("ACCESS_DENIED", "Native policy account is not active", 403)
            management = DirectoryManagement(preparation, self.core,
                request_id=request_id, cloud_mode=self.cloud_mode)
            try:
                yield DirectoryPolicyService(management)
            finally:
                management.epoch = None
                management.current_subject = None
                management.is_owner = False
                management.is_library_admin = False
                # preparation_scope owns rollback/close on every exit, including
                # failed assembly; the factory never borrows a global connection.
