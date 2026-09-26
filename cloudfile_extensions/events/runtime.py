"""Owned native-session audit query scopes; no export or route registration."""
from contextlib import contextmanager

from ..authorization.runtime import PolicyServiceFactory, AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.preparation import SubjectPreparation
from ..resources.runtime import expected_subject
from .authorized_query import AuthorizedAuditQuery


class AuditQueryFactory(PolicyServiceFactory):
    def __init__(self, *, authenticate, preparation_scope, core, cloud_mode, secret, redact):
        super().__init__(authenticate=authenticate, preparation_scope=preparation_scope,
            core=core, cloud_mode=cloud_mode)
        if not isinstance(secret, bytes) or len(secret) < 32 or not callable(redact):
            raise ValueError("fixed audit cursor secret and deployment redaction required")
        self.secret, self.redact = secret, redact

    @contextmanager
    def __call__(self, request, request_id):
        actor = self.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated audit identity is required", 401)
        expected_subject(request, actor)
        identifier(request_id)
        with self.preparation_scope(actor.user_id, request_id) as preparation:
            if not isinstance(preparation, SubjectPreparation) or preparation.actor != actor.user_id:
                raise ContractError("AUDIT_UNAVAILABLE", "Audit runtime identity is unavailable", 503)
            if (preparation.state.username(actor.user_id) != actor.native_username
                    or not preparation.state.account_active(actor.user_id)):
                raise ContractError("ACCESS_DENIED", "Audit session identity is not active or consistent", 403)
            service = AuthorizedAuditQuery(preparation, self.core, cloud_mode=self.cloud_mode,
                request_id=request_id, secret=self.secret, redact=self.redact)
            try:
                yield service
            finally:
                service.cursor = service.repo_id = service.epoch = None
                authority = service.authority
                authority.epoch = authority.current_subject = authority.effective_access = None
                authority.is_owner = False
