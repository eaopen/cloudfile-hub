"""Durable dispatch intent/receipt, fenced by the actual search outbox lease.

Submitting without a receipt means unknown submission, never permission to
resubmit. Recovery must reconcile or rebuild before unblocking the stream.
"""
import re
from contextlib import contextmanager

from ..common.errors import ContractError
from ..events.outbox import EventClaim
from .generations import SearchGenerationStore
from .initialization import SearchInitializationStore
from ..tags.definitions import uuid_value


class SearchTaskStore:
    def __init__(self, connection):
        if not connection.get_autocommit():
            raise ValueError("dedicated autocommit connection required")
        self.connection = connection

    @contextmanager
    def _owned(self, claim):
        if not isinstance(claim, EventClaim) or claim.consumer != "search":
            raise ValueError("actual search event claim required")
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                sql.execute("SELECT event_id FROM cf_event_outbox WHERE event_id=%s AND search_state='running' AND search_owner=%s AND search_epoch=%s AND search_expiry>UTC_TIMESTAMP(6) FOR UPDATE", (claim.event_id, claim.owner, claim.epoch))
                if sql.fetchone() is None:
                    raise ContractError("WORKER_LEASE_LOST", "Search event lease is no longer current", 409)
                yield sql
            self.connection.commit()
        finally:
            self.connection.rollback()

    @staticmethod
    def _key(claim, generation, step):
        if not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", generation) or type(step) is not int or not 0 <= step <= 10000:
            raise ValueError("trusted bounded task identity required")
        return claim.event_id, generation, step

    def prepare(self, claim, *, generation, step, payload_hash):
        key = self._key(claim, generation, step)
        if not isinstance(payload_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", payload_hash):
            raise ValueError("exact prepared payload hash required")
        with self._owned(claim) as sql:
            sql.execute("SELECT payload_hash,state,task_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s AND step=%s FOR UPDATE", key)
            row = sql.fetchone()
            if row is not None:
                if row[0] != payload_hash:
                    raise ContractError("SEARCH_TASK_CONFLICT", "Search task payload changed", 409)
                if (row[1] not in ("prepared", "submitting", "submitted", "succeeded") or
                        (row[1] in ("prepared", "submitting") and row[2] is not None) or
                        (row[1] in ("submitted", "succeeded") and (type(row[2]) is not int or not 0 <= row[2] <= 2 ** 63 - 1))):
                    raise ContractError("SEARCH_TASK_CONFLICT", "Stored search task is invalid", 409)
                return dict(state=row[1], task_id=row[2])
            sql.execute("INSERT INTO cf_search_task(event_id,index_generation,step,payload_hash,state,created_at,updated_at) VALUES(%s,%s,%s,%s,'prepared',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))", (*key, payload_hash))
            return dict(state="prepared", task_id=None)

    def _transition(self, claim, generation, step, previous, state, task_id=None):
        key = self._key(claim, generation, step)
        with self._owned(claim) as sql:
            sql.execute("UPDATE cf_search_task SET state=%s,task_id=COALESCE(%s,task_id),updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s AND step=%s AND state=%s", (state, task_id, *key, previous))
            if sql.rowcount != 1:
                raise ContractError("SEARCH_TASK_CONFLICT", "Search task transition is not current", 409)

    def mark_submitting(self, claim, *, generation, step):
        # Commit before the one network dispatch. Never reset submitting here.
        self._transition(claim, generation, step, "prepared", "submitting")

    def _incremental_gate(self, sql, claim, generation):
        # Read the actual locked event stream, not a caller-selected repository.
        sql.execute("SELECT stream FROM cf_event_outbox WHERE event_id=%s FOR UPDATE", (claim.event_id,))
        row = sql.fetchone()
        if row is None or not isinstance(row[0], str):
            raise ContractError("SEARCH_PLAN_CONFLICT", "Search event stream is invalid", 409)
        stream = row[0]
        if stream.startswith("repo."):
            repo = uuid_value(stream[5:])
            sql.execute("SELECT state FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s FOR UPDATE", (generation, repo))
            rebuild = sql.fetchone()
            if rebuild is not None and rebuild[0] != "scanned":
                raise ContractError("SEARCH_REBUILD_PENDING", "Library rebuild must finish before incremental writes", 503)
        elif stream == "security":
            sql.execute("SELECT repo_id FROM cf_search_rebuild WHERE generation=%s AND state<>'scanned' LIMIT 1 FOR UPDATE", (generation,))
            if sql.fetchone() is not None:
                raise ContractError("SEARCH_REBUILD_PENDING", "Global incremental writes wait for rebuild", 503)
        else:
            raise ContractError("SEARCH_PLAN_CONFLICT", "Search event stream is invalid", 409)

    def mark_dispatch_intent(self, claim, *, generation, step, index):
        key = self._key(claim, generation, step)
        with self._owned(claim) as sql:
            SearchGenerationStore(self.connection).require_dispatch(sql, generation, index)
            SearchInitializationStore(self.connection).require_complete(sql, generation, index)
            self._incremental_gate(sql, claim, generation)
            sql.execute("UPDATE cf_search_task SET state='submitting',updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s AND step=%s AND state='prepared' AND task_id IS NULL", key)
            if sql.rowcount != 1:
                raise ContractError("SEARCH_TASK_CONFLICT", "Search dispatch intent is not current", 409)

    def _planning_gate(self, sql, claim, generation, index=None):
        sql.execute("SELECT index_uid,state FROM cf_search_generation WHERE generation=%s FOR UPDATE", (generation,))
        row = sql.fetchone()
        if row is None or row[1] != "building" or (index is not None and row[0] != index):
            raise ContractError("SEARCH_GENERATION_RETIRED", "Search generation cannot prepare plans", 409)
        SearchGenerationStore._identity(generation, row[0])
        SearchInitializationStore(self.connection).require_complete(sql, generation, row[0])
        self._incremental_gate(sql, claim, generation)

    def record_task(self, claim, *, generation, step, task_id):
        if type(task_id) is not int or not 0 <= task_id <= 2 ** 63 - 1:
            raise ValueError("exact accepted task id required")
        self._transition(claim, generation, step, "submitting", "submitted", task_id)

    def dispatch(self, claim, *, generation, step, index, send):
        """One dispatch under current lease and permanent generation row locks.

        Intent was committed separately. Failure here rolls back only the
        receipt, leaving submitting for reconciliation, never retry permission.
        Retirement waits for this bounded network operation to finish; delayed
        remote application remains confined to the immutable physical index.
        """
        key = self._key(claim, generation, step)
        if not callable(send):
            raise ValueError("single bounded private dispatch required")
        registry = SearchGenerationStore(self.connection)
        with self._owned(claim) as sql:
            registry.require_dispatch(sql, generation, index)
            SearchInitializationStore(self.connection).require_complete(sql, generation, index)
            self._incremental_gate(sql, claim, generation)
            sql.execute("SELECT state,task_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s AND step=%s FOR UPDATE", key)
            if sql.fetchone() != ("submitting", None):
                raise ContractError("SEARCH_TASK_CONFLICT", "Search dispatch intent is not current", 409)
            task_id = send()
            if type(task_id) is not int or not 0 <= task_id <= 2 ** 63 - 1:
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Search receipt is invalid", 503)
            sql.execute("UPDATE cf_search_task SET state='submitted',task_id=%s,updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s AND step=%s AND state='submitting' AND task_id IS NULL", (task_id, *key))
            if sql.rowcount != 1:
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Search receipt could not be stored", 503)
            return task_id

    def require_initialized(self, claim, *, generation, index):
        # Early check avoids poisoning intent for a known incomplete index.
        # Dispatch rechecks under its retained locks; this is not the final gate.
        with self._owned(claim) as sql:
            SearchGenerationStore(self.connection).require_dispatch(sql, generation, index)
            SearchInitializationStore(self.connection).require_complete(sql, generation, index)
            self._incremental_gate(sql, claim, generation)

    def record_succeeded(self, claim, *, generation, step):
        # Caller must have checked exact uid/index/type succeeded via task API.
        self._transition(claim, generation, step, "submitted", "succeeded")

    def complete_event(self, claim, *, generation, payload_hashes):
        """Trusted full event plan, not a caller-selected subset of steps.

        No network inside this transaction. Match every stored step and reject
        unresolved tasks from any other generation before advancing the stream.
        """
        self._key(claim, generation, 0)
        if (not isinstance(payload_hashes, list) or not 1 <= len(payload_hashes) <= 10001 or
                any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in payload_hashes)):
            raise ValueError("complete ordered event payload hashes required")
        with self._owned(claim) as sql:
            sql.execute("SELECT step,payload_hash,state,task_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s ORDER BY step FOR UPDATE", (claim.event_id, generation))
            rows = sql.fetchall()
            if (len(rows) != len(payload_hashes) or any(row[0] != step or row[1] != payload_hashes[step] or
                    row[2] != "succeeded" or type(row[3]) is not int or not 0 <= row[3] <= 2 ** 63 - 1 for step, row in enumerate(rows))):
                raise ContractError("SEARCH_TASK_PENDING", "Search event steps are incomplete", 409)
            sql.execute("SELECT event_id FROM cf_search_task WHERE event_id=%s AND index_generation<>%s AND state<>'succeeded' LIMIT 1 FOR UPDATE", (claim.event_id, generation))
            if sql.fetchone() is not None:
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Other index generation requires recovery", 503)
            sql.execute("UPDATE cf_event_outbox SET search_state='done',search_expiry=NULL,search_error=NULL WHERE event_id=%s AND search_state='running' AND search_owner=%s AND search_epoch=%s AND search_expiry>UTC_TIMESTAMP(6)", (claim.event_id, claim.owner, claim.epoch))
            if sql.rowcount != 1:
                raise ContractError("WORKER_LEASE_LOST", "Search event lease expired before completion", 409)
