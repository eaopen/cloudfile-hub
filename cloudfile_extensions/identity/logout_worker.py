"""Bounded, fenced execution of already accepted OIDC logout notifications."""
import json

from ..common.errors import ContractError
from ..common.validation import object_fields
from ..jobs.authority import scope_locks
from ..jobs.worker import Execution, Handler, JobResult
from .logout_jobs import BackchannelJobs
from .logout_token import LogoutNotification
from .session_delete import NativeDBSessionDelete


class BackchannelWorker:
    def __init__(self, jobs, deletion, *, page_size=100):
        if (not isinstance(jobs, BackchannelJobs)
                or not isinstance(deletion, NativeDBSessionDelete)
                or deletion.index is not jobs.index
                or type(page_size) is not int or not 1 <= page_size <= 100):
            raise ValueError("same-connection native logout assembly required")
        self.jobs, self.deletion, self.page_size = jobs, deletion, page_size
        self.handler = Handler(self.execute)

    def execute(self, execution):
        if not isinstance(execution, Execution) or execution.store is not self.jobs.store:
            raise ValueError("actual owned job execution required")
        claim = execution.claim
        fields = ("issuer", "client_id", "jti", "subject", "session_id", "issued_at", "expires_at")
        object_fields(claim.request, fields)
        notification = LogoutNotification(**claim.request)
        index = self.jobs.index
        if (claim.kind != self.jobs.KIND or claim.scope != index.scope
                or (notification.issuer, notification.client_id) != (index.issuer, index.client_id)
                or type(notification.issued_at) is not int
                or type(notification.expires_at) is not int
                or not 0 <= notification.issued_at < notification.expires_at
                or (notification.subject is None and notification.session_id is None)):
            raise ContractError("INVALID_REQUEST", "Invalid accepted logout job", 400)
        # Expiration is an intake condition, not a deadline for durable recovery.
        # Never re-accept a JWT here or abandon an already accepted notification.
        def current(cursor):
            cursor.execute("SELECT status,lease_owner,lease_epoch,lease_expiry>UTC_TIMESTAMP(6),"
                "actor,actor_kind,kind,scope_id,request_json,barrier_active "
                "FROM cf_background_job WHERE job_id=%s FOR UPDATE", (claim.job_id,))
            rows = cursor.fetchall()
            if (len(rows) != 1 or rows[0][:7] != ("running", claim.owner, claim.epoch, 1,
                    self.jobs.actor, "service", self.jobs.KIND)
                    or json.loads(rows[0][7]) != index.scope
                    or json.loads(rows[0][8]) != claim.request or rows[0][9] != 0):
                raise ContractError("WORKER_LEASE_LOST", "Logout lease is no longer current", 409)

        while True:
            store = self.jobs.store
            with scope_locks(store.connection, [index.scope]), store._transaction():
                with store.connection.cursor() as cursor:
                    current(cursor)
                    targets = index.targets(cursor, notification, limit=self.page_size)
                    deleted = sum(self.deletion.delete(cursor, key, notification) for key in targets)
                    current(cursor)
                    if targets:
                        store._record(cursor, dict(job_id=claim.job_id, actor=self.jobs.actor,
                            actor_kind="service", scope=index.scope), action="identity.logout.sessions",
                            result="success")
            # No session identifiers or raw notification claims enter checkpoints.
            # Retry reconciles the actual remaining rows, not historical counts.
            execution.checkpoint(step="sessions_removed" if targets else "sessions_drained",
                value=dict(page_references=len(targets), page_sessions=deleted))
            if not targets:
                return JobResult()
