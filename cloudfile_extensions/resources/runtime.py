"""Owned authenticated host resource service scopes; no route registration."""
from contextlib import contextmanager

from ..authorization.runtime import PolicyServiceFactory, AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.preparation import SubjectPreparation
from .service import ResourceService


class ResourceServiceFactory(PolicyServiceFactory):
    def __init__(self, *, authenticate, preparation_scope, core, cloud_mode,
                 secret, lifecycle_reader):
        super().__init__(authenticate=authenticate, preparation_scope=preparation_scope,
            core=core, cloud_mode=cloud_mode)
        if not isinstance(secret, bytes) or len(secret) < 32 or not callable(lifecycle_reader):
            raise ValueError("fixed resource validator secret and native lifecycle reader required")
        self.secret, self.lifecycle_reader = secret, lifecycle_reader

    @contextmanager
    def __call__(self, request, request_id):
        actor = self.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated resource identity is required", 401)
        identifier(request_id)
        with self.preparation_scope(actor.user_id, request_id) as preparation:
            if not isinstance(preparation, SubjectPreparation) or preparation.actor != actor.user_id:
                raise ContractError("POLICY_UNAVAILABLE", "Resource runtime identity is unavailable", 503)
            if preparation.state.username(actor.user_id) != actor.native_username:
                raise ContractError("ACCESS_DENIED", "Native resource identity does not match", 403)
            if not preparation.state.account_active(actor.user_id):
                raise ContractError("ACCESS_DENIED", "Native resource account is not active", 403)
            service = ResourceService(preparation, self.core, cloud_mode=self.cloud_mode,
                request_id=request_id, secret=self.secret, lifecycle_reader=self.lifecycle_reader)
            try:
                yield service
            finally:
                for authority in (service.read_authority, service.write_authority):
                    authority.epoch = None
                    authority.current_subject = None
                    authority.is_owner = False
                # The owned preparation context rolls back and closes its SQL
                # connection on every exit. Secrets never enter request/DTO data.
