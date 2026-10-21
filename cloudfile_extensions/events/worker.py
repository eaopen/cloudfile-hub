"""Trusted audit.export handler with owned current user authority.

Uses the persisted job actor, not a request actor or an administrative session.
Deployment must register this handler explicitly; no worker is started here.
"""
from uuid import uuid4

from ..authorization.core import PolicyCore
from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.preparation import SubjectPreparation
from ..jobs.worker import Execution
from .authorized_export import AuthorizedAuditCSV
from .authorized_query import AuthorizedAuditQuery
from .export_job import AuditExportJob
from .privacy import default_redact


class AuthorizedAuditExportJob:
    def __init__(self, *, preparation_scope, core, cloud_mode, secret, result_root,
                 redact=None):
        import os
        if (not callable(preparation_scope) or not isinstance(core, PolicyCore)
                or type(cloud_mode) is not bool or not isinstance(secret, bytes)
                or len(secret) < 32 or not isinstance(result_root, str)
                or not os.path.isabs(result_root)):
            raise ValueError("trusted owned audit worker configuration required")
        if redact is None:
            redact = default_redact
        if not callable(redact):
            raise ValueError("trusted audit redaction required")
        self.preparation_scope, self.core = preparation_scope, core
        self.cloud_mode, self.secret = cloud_mode, secret
        self.result_root, self.redact = result_root, redact

    def __call__(self, execution):
        if not isinstance(execution, Execution):
            raise ValueError("actual job execution required")
        claim = execution.claim
        job = execution.store.get(claim.job_id)
        if (claim.kind != "audit.export" or job["kind"] != claim.kind
                or job["scope"] != claim.scope or job["actor_kind"] != "user"
                or job["barrier_active"] or claim.scope.get("type") != "repo"
                or claim.scope.get("provider") != "cloudfile"):
            raise ContractError("INVALID_REQUEST", "Invalid audit export user scope", 400)
        actor = identifier(job["actor"], maximum=225)
        with self.preparation_scope(actor, str(uuid4())) as preparation:
            if (not isinstance(preparation, SubjectPreparation) or preparation.actor != actor
                    or preparation.state.connection is execution.store.connection):
                raise ContractError("AUDIT_UNAVAILABLE", "Owned audit worker authority is unavailable", 503)
            if (not preparation.state.username(actor)
                    or not preparation.state.account_active(actor)):
                raise ContractError("ACCESS_DENIED", "Audit export account is not active or bound", 403)
            query = AuthorizedAuditQuery(preparation, self.core, cloud_mode=self.cloud_mode,
                request_id=str(uuid4()), secret=self.secret, redact=self.redact)
            exporter = AuthorizedAuditCSV(query, repo_id=claim.scope["external_id"])
            # Existing handler checkpoints the real lease, captures a protected
            # cutoff, generates bounded pages, reauthorizes and privately stages
            # an epoch-specific result. JobWorker.complete remains the fence.
            return AuditExportJob(exporter, result_root=self.result_root)(execution)
