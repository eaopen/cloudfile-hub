"""Durable dispatch intent/receipt, fenced by the actual search outbox lease.

Submitting without a receipt means unknown submission, never permission to
resubmit. Recovery must reconcile or rebuild before unblocking the stream.
"""
import re
from contextlib import contextmanager

from ..common.errors import ContractError
from ..events.outbox import EventClaim


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

    def record_task(self, claim, *, generation, step, task_id):
        if type(task_id) is not int or not 0 <= task_id <= 2 ** 63 - 1:
            raise ValueError("exact accepted task id required")
        self._transition(claim, generation, step, "submitting", "submitted", task_id)

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
