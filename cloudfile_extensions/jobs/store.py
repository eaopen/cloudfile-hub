"""Durable jobs with idempotency, scoped barriers and fenced worker leases."""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from uuid import uuid4

from ..common.errors import ContractError
from ..common.validation import identifier
from ..events.outbox import EventWriter
from .authority import canonical_scope, scope_locks


def canonical(value):
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        raise ContractError("INVALID_REQUEST", "Invalid job request", 400) from None
    if len(text.encode()) > 16384:
        raise ContractError("INVALID_REQUEST", "Job request exceeds the limit", 400)
    return text


def normalize_scope(scope):
    return canonical_scope(scope)


@dataclass(frozen=True)
class JobClaim:
    job_id: str
    owner: str
    epoch: int
    kind: str
    scope: dict
    request: dict


@dataclass(frozen=True)
class BarrierProof:
    """Only a trusted coordinator may return proof after projection/epoch checks."""
    job_id: str
    lease_epoch: int


class JobStore:
    def __init__(self, connection, *, event_writer=None):
        if not connection.get_autocommit():
            raise ValueError("job store requires its own autocommit connection")
        self.connection = connection
        self.event_writer = EventWriter() if event_writer is None else event_writer

    def _record(self, cursor, job, *, action, result, actor=None, actor_kind=None, source="hub"):
        event = {"event_id": str(uuid4()), "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "request_id": job["job_id"], "job_id": job["job_id"], "actor_user_id": job["actor"] if actor is None else actor,
                 "actor_kind": job["actor_kind"] if actor_kind is None else actor_kind,
                 "source": source, "action": action, "result": result}
        if job["scope"]["type"] == "repo":
            event["repo_id"] = job["scope"]["external_id"]
        self.event_writer.append(cursor, event)

    @contextmanager
    def _transaction(self):
        self.connection.begin()
        try:
            yield
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    @contextmanager
    def _idempotency_lock(self, actor, actor_kind, kind, key):
        name = "cf.job." + hashlib.sha256(canonical([actor, actor_kind, kind, key]).encode()).hexdigest()[:48]
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s,5)", (name,))
            if cursor.fetchone()[0] != 1:
                raise ContractError("JOB_BUSY", "Job submission is busy", 503)
        try:
            yield
        finally:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (name,))

    def submit(self, *, actor, actor_kind, kind, scope, request, idempotency_key, barrier=False):
        identifier(actor)
        if actor_kind not in {"user", "service"} or type(barrier) is not bool:
            raise ContractError("INVALID_REQUEST", "Invalid job actor or barrier", 400)
        if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", kind):
            raise ContractError("INVALID_REQUEST", "Invalid job kind", 400)
        if not isinstance(idempotency_key, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", idempotency_key):
            raise ContractError("INVALID_REQUEST", "Invalid idempotency key", 400)
        if not isinstance(request, dict):
            raise ContractError("INVALID_REQUEST", "Invalid job request", 400)
        scope_json = normalize_scope(scope)
        request_json = canonical(request)
        digest = hashlib.sha256(canonical([scope, request, barrier]).encode()).hexdigest()
        # Establish the barrier under the same scope lock as native publication.
        # Effects and lock ownership share this exact SQL connection.
        with scope_locks(self.connection, [scope]), self._idempotency_lock(actor, actor_kind, kind, idempotency_key), self._transaction():
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT job_id,request_digest FROM cf_background_job "
                               "WHERE actor=%s AND actor_kind=%s AND kind=%s AND idempotency_key=%s",
                               (actor, actor_kind, kind, idempotency_key))
                existing = cursor.fetchone()
                if existing:
                    if existing[1] != digest:
                        raise ContractError("IDEMPOTENCY_CONFLICT", "Idempotency key has a different request", 409)
                    return existing[0], False
                job_id = str(uuid4())
                cursor.execute("INSERT INTO cf_background_job(job_id,kind,actor,actor_kind,scope_type,scope_id,scope_hash,"
                               "request_digest,idempotency_key,request_json,status,step,barrier_active,next_attempt_at,created_at,updated_at) "
                               "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'queued','accepted',%s,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",
                               (job_id, kind, actor, actor_kind, scope["type"], scope_json,
                                hashlib.sha256(scope_json.encode()).hexdigest(), digest, idempotency_key, request_json, int(barrier)))
                self._record(cursor, {"job_id": job_id, "actor": actor, "actor_kind": actor_kind, "scope": scope},
                             action="job.accepted", result="attempted")
                return job_id, True

    def active_barrier(self, scope):
        scope_json = normalize_scope(scope)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT scope_id FROM cf_background_job WHERE scope_type=%s AND scope_hash=%s AND barrier_active=1",
                           (scope["type"], hashlib.sha256(scope_json.encode()).hexdigest()))
            # Compare the original scope even after a digest match.
            return any(row[0] == scope_json for row in cursor.fetchall())

    def get(self, job_id):
        identifier(job_id, maximum=36)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT job_id,kind,actor,actor_kind,scope_id,status,step,barrier_active,lease_epoch,"
                           "attempts,checkpoint,result_ref,error_code FROM cf_background_job WHERE job_id=%s", (job_id,))
            row = cursor.fetchone()
        if row is None:
            raise ContractError("NOT_FOUND", "Job does not exist", 404)
        result = dict(zip(("job_id", "kind", "actor", "actor_kind", "scope", "status", "step", "barrier_active",
                           "lease_epoch", "attempts", "checkpoint", "result_ref", "error_code"), row))
        result["scope"] = json.loads(result["scope"])
        result["barrier_active"] = bool(result["barrier_active"])
        result["checkpoint"] = json.loads(result["checkpoint"]) if result["checkpoint"] else None
        return result

    def claim(self, owner, *, kinds, lease_seconds=30):
        identifier(owner, maximum=128)
        if (not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", owner) or not isinstance(kinds, tuple) or not kinds or len(kinds) > 16 or
                any(not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", kind) for kind in kinds) or
                type(lease_seconds) is not int or not 1 <= lease_seconds <= 300):
            raise ValueError("invalid worker claim configuration")
        with self._transaction(), self.connection.cursor() as cursor:
            placeholders = ",".join(["%s"] * len(kinds))
            cursor.execute("SELECT job_id,kind,scope_id,request_json,lease_epoch FROM cf_background_job WHERE kind IN (" +
                           placeholders + ") AND ((status='queued' AND next_attempt_at<=UTC_TIMESTAMP(6)) OR "
                           "(status='running' AND lease_expiry<=UTC_TIMESTAMP(6))) "
                           "ORDER BY created_at,job_id LIMIT 1 FOR UPDATE SKIP LOCKED", kinds)
            row = cursor.fetchone()
            if row is None:
                return None
            epoch = row[4] + 1
            cursor.execute("UPDATE cf_background_job SET status='running',lease_owner=%s,lease_epoch=%s,"
                           "lease_expiry=TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6)),attempts=attempts+1,updated_at=UTC_TIMESTAMP(6) WHERE job_id=%s",
                           (owner, epoch, lease_seconds, row[0]))
            return JobClaim(row[0], owner, epoch, row[1], json.loads(row[2]), json.loads(row[3]))

    def _update(self, claim, sql, values):
        with self.connection.cursor() as cursor:
            cursor.execute(sql + " WHERE job_id=%s AND status='running' AND lease_owner=%s AND lease_epoch=%s "
                           "AND lease_expiry>UTC_TIMESTAMP(6)", (*values, claim.job_id, claim.owner, claim.epoch))
            if cursor.rowcount != 1:
                raise ContractError("WORKER_LEASE_LOST", "Worker lease is no longer current", 409)

    def checkpoint(self, claim, *, step, checkpoint, lease_seconds=30):
        if not isinstance(step, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", step):
            raise ValueError("invalid worker step")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("invalid worker lease")
        self._update(claim, "UPDATE cf_background_job SET step=%s,checkpoint=%s,lease_expiry=TIMESTAMPADD(SECOND,%s,UTC_TIMESTAMP(6)),updated_at=UTC_TIMESTAMP(6)",
                     (step, canonical(checkpoint), lease_seconds))

    def fail(self, claim, *, code):
        if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
            raise ValueError("invalid safe error code")
        # Failed work remains fenced until explicit successful recovery.
        with self._transaction():
            self._update(claim, "UPDATE cf_background_job SET status='failed',error_code=%s,lease_expiry=NULL,updated_at=UTC_TIMESTAMP(6)", (code,))
            with self.connection.cursor() as cursor:
                self._record(cursor, self.get(claim.job_id), action="job.failed", result="failed",
                             actor=claim.owner, actor_kind="service", source="worker")

    def cancel(self, job_id, *, actor, actor_kind):
        # The management caller must authorize the exact job scope before calling.
        return self._management_transition(job_id, status="cancelled", allowed=("queued", "running", "failed"),
                                           actor=actor, actor_kind=actor_kind, action="job.cancelled")

    def retry(self, job_id, *, actor, actor_kind):
        return self._management_transition(job_id, status="queued", allowed=("failed", "cancelled"),
                                           actor=actor, actor_kind=actor_kind, action="job.retried")

    def retry_failed(self, job_id, *, actor, actor_kind):
        # A fresh authenticated recovery request must not undo a concurrent
        # administrator cancellation between its read and this row lock.
        return self._management_transition(job_id, status="queued", allowed=("failed",),
                                           actor=actor, actor_kind=actor_kind, action="job.retried")

    def _management_transition(self, job_id, *, status, allowed, actor, actor_kind, action):
        identifier(actor)
        if actor_kind not in {"user", "service"}:
            raise ContractError("INVALID_REQUEST", "Invalid management actor", 400)
        with self._transaction(), self.connection.cursor() as cursor:
            cursor.execute("SELECT status FROM cf_background_job WHERE job_id=%s FOR UPDATE", (job_id,))
            row = cursor.fetchone()
            if row is None:
                raise ContractError("NOT_FOUND", "Job does not exist", 404)
            if row[0] in allowed:
                cursor.execute("UPDATE cf_background_job SET status=%s,lease_expiry=NULL,next_attempt_at=UTC_TIMESTAMP(6),"
                               "updated_at=UTC_TIMESTAMP(6) WHERE job_id=%s", (status, job_id))
                self._record(cursor, self.get(job_id), action=action, result="succeeded", actor=actor, actor_kind=actor_kind)
        return self.get(job_id)

    def complete(self, claim, *, result_ref=None, barrier_guard=None):
        current = self.get(claim.job_id)
        if current["scope"] != claim.scope:
            raise ContractError("WORKER_LEASE_LOST", "Worker scope is no longer current", 409)
        if current["barrier_active"]:
            if not callable(barrier_guard):
                raise ContractError("BARRIER_RECONCILIATION_REQUIRED", "Barrier needs verified reconciliation", 409)
            # The trusted reconciliation guard enters first so it can acquire
            # provider/user before repo scopes. Its SQL locks must use this exact
            # connection; never call a separately locking RPC while owning them.
            with barrier_guard(claim) as proof:
                if proof != BarrierProof(claim.job_id, claim.epoch):
                    raise ContractError("BARRIER_RECONCILIATION_REQUIRED", "Invalid reconciliation proof", 409)
                with scope_locks(self.connection, [current["scope"]]):
                    self._finish(claim, result_ref)
        else:
            self._finish(claim, result_ref)

    def _finish(self, claim, result_ref):
        if result_ref is not None:
            identifier(result_ref, maximum=4096)
        with self._transaction():
            self._update(claim, "UPDATE cf_background_job SET status='succeeded',step='finished',barrier_active=0,"
                         "result_ref=%s,error_code=NULL,lease_expiry=NULL,updated_at=UTC_TIMESTAMP(6)", (result_ref,))
            with self.connection.cursor() as cursor:
                self._record(cursor, self.get(claim.job_id), action="job.completed", result="succeeded",
                             actor=claim.owner, actor_kind="service", source="worker")
