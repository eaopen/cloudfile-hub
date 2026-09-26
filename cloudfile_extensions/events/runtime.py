"""Owned native-session audit query scopes; no export or route registration."""
from contextlib import contextmanager

from ..authorization.runtime import PolicyServiceFactory, AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.preparation import SubjectPreparation
from ..resources.runtime import expected_subject
from .authorized_query import AuthorizedAuditQuery
from .privacy import default_redact


class AuditQueryFactory(PolicyServiceFactory):
    def __init__(self, *, authenticate, preparation_scope, core, cloud_mode, secret, redact=None,
                 result_root=None):
        super().__init__(authenticate=authenticate, preparation_scope=preparation_scope,
            core=core, cloud_mode=cloud_mode)
        if redact is None:
            redact = default_redact
        if not isinstance(secret, bytes) or len(secret) < 32 or not callable(redact):
            raise ValueError("fixed audit cursor secret and deployment redaction required")
        self.secret, self.redact = secret, redact
        import os
        if result_root is not None and (not isinstance(result_root, str) or not os.path.isabs(result_root)):
            raise ValueError("trusted absolute audit result root required")
        self.result_root = result_root

    def export_handler(self, *, result_root):
        """Explicit trusted worker assembly; does not start or enable a worker."""
        from .worker import AuthorizedAuditExportJob
        if self.result_root is not None and result_root != self.result_root:
            raise ValueError("audit worker and result delivery roots must match")
        return AuthorizedAuditExportJob(preparation_scope=self.preparation_scope,
            core=self.core, cloud_mode=self.cloud_mode, secret=self.secret,
            redact=self.redact, result_root=result_root)

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
                request_id=request_id, secret=self.secret, redact=self.redact, result_root=self.result_root)
            try:
                yield service
            finally:
                service.cursor = service.repo_id = service.epoch = None
                authority = service.authority
                authority.epoch = authority.current_subject = authority.effective_access = None
                authority.is_owner = False
