"""Single-user forced refresh execution with real job lease fencing.

Trusted submission authorization and barrier reconciliation are separate. This
handler never bypasses a persistent barrier and cannot refresh arbitrary scopes.
"""
from contextlib import contextmanager
import json

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from ..jobs.worker import Execution, JobResult
from .preparation import SubjectPreparation
from ..jobs.authority import scope_locks
from ..events.outbox import EventWriter
from datetime import datetime, timezone
from uuid import uuid5, NAMESPACE_URL


class UserRefreshJob:
    KIND = "authorization.refresh.user"

    def __init__(self, *, preparation_factory, provider):
        if not callable(preparation_factory):
            raise ValueError("trusted same-connection preparation factory required")
        self.factory = preparation_factory
        self.provider = identifier(provider, maximum=32)

    def __call__(self, execution):
        if not isinstance(execution, Execution):
            raise ValueError("actual refresh job execution required")
        claim = execution.claim
        object_fields(claim.request, ("userId",), ("reason",))
        if "reason" in claim.request:
            reason = claim.request["reason"]
            if (not isinstance(reason, str) or not reason.strip() or len(reason) > 512
                    or any(ord(char) < 32 for char in reason)):
                raise ContractError("INVALID_REQUEST", "Invalid refresh reason", 400)
        user = identifier(claim.request["userId"], maximum=225)
        scope = dict(type="user", provider=self.provider, external_id=user)
        if claim.kind != self.KIND or claim.scope != scope:
            raise ContractError("INVALID_REQUEST", "Invalid user refresh scope", 400)
        connection = execution.store.connection
        def assert_claim():
            with connection.cursor() as cursor:
                cursor.execute("SELECT status,lease_owner,lease_epoch,lease_expiry>UTC_TIMESTAMP(6),"
                    "kind,scope_id,request_json,barrier_active,actor,actor_kind FROM cf_background_job WHERE job_id=%s FOR UPDATE",
                    (claim.job_id,))
                rows = cursor.fetchall()
            if (len(rows) != 1 or rows[0][:5] != ("running", claim.owner, claim.epoch, 1, self.KIND)
                    or json.loads(rows[0][5]) != scope or json.loads(rows[0][6]) != claim.request
                    or rows[0][7] != 0):
                raise ContractError("WORKER_LEASE_LOST", "User refresh lease is no longer current", 409)
            identifier(rows[0][8], maximum=225)
            if rows[0][9] not in {"user", "service"}:
                raise ContractError("INVALID_REQUEST", "Invalid refresh task actor", 400)
            return rows[0][8], rows[0][9]
        assert_claim()
        with self.factory(user, execution) as preparation:
            if (not isinstance(preparation, SubjectPreparation) or preparation.actor != user
                    or preparation.state.connection is not connection
                    or preparation.state.provider != self.provider):
                raise ValueError("same-connection own-user preparation required")
            original_generation = preparation.projector.assert_generation
            original_guard = preparation.contexts.refresh_guard
            def generation(subject, epoch):
                original_generation(subject, epoch)
                assert_claim()
            @contextmanager
            def guard(subject, epoch, *, phase):
                with original_guard(subject, epoch, phase=phase) as ownership:
                    def proof():
                        ownership()
                        assert_claim()
                    proof()
                    yield proof
                    proof()
            preparation.projector.assert_generation = generation
            preparation.contexts.refresh_guard = guard
            try:
                value = preparation.prepare(user, trigger="force")
                scopes = [dict(type="provider", provider=self.provider, external_id=self.provider), scope]
                with scope_locks(connection, scopes):
                    connection.begin()
                    try:
                        actor, actor_kind = assert_claim()
                        current = preparation.contexts.current(user)
                        if current is None or current["context_epoch"] != value["context_epoch"]:
                            raise ContractError("SUBJECT_UNAVAILABLE", "Refreshed subject changed", 503)
                        event = dict(event_id=str(uuid5(NAMESPACE_URL, "cf.refresh:" + claim.job_id
                            + ":" + str(claim.epoch) + ":" + value["context_epoch"])),
                            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            request_id=claim.job_id, job_id=claim.job_id, actor_user_id=actor,
                            actor_kind=actor_kind, source="worker", action="authorization.subject.refreshed",
                            result="succeeded", target_user_id=user, subject_revision=value["context_epoch"])
                        if "reason" in claim.request:
                            event["reason"] = claim.request["reason"]
                        with connection.cursor() as cursor:
                            EventWriter().append(cursor, event)
                        execution.checkpoint(step="subject_refreshed", value={"context_epoch": value["context_epoch"]})
                        connection.commit()
                    finally:
                        connection.rollback()
            finally:
                preparation.projector.assert_generation = original_generation
                preparation.contexts.refresh_guard = original_guard
        return JobResult()
