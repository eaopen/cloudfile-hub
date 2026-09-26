"""One bounded durable search step; caller owns ordered event completion."""
import hashlib
import json

from ..common.errors import ContractError
from .task_store import SearchTaskStore
from .tasks import MeilisearchTasks


class SearchStepExecution:
    def __init__(self, store, client):
        if not isinstance(store, SearchTaskStore) or not isinstance(client, MeilisearchTasks):
            raise ValueError("actual durable task store and private task client required")
        self.store, self.client = store, client

    def advance(self, claim, *, generation, step, operation, payload):
        if operation not in ("replace", "delete"):
            raise ValueError("explicit index mutation required")
        # Freeze exact input before hashing/dispatch, no caller mutation in flight.
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > 1048576:
            raise ValueError("bounded search step required")
        frozen = json.loads(raw.decode("utf-8"))
        if not isinstance(frozen, list) or not 1 <= len(frozen) <= 100:
            raise ValueError("bounded search batch required")
        digest = hashlib.sha256(b"cf.search.step.v1\n" + self.client.index.encode("ascii") + b"\n" + operation.encode("ascii") + b"\n" + raw).hexdigest()
        identity = dict(generation=generation, step=step)
        receipt = self.store.prepare(claim, payload_hash=digest, **identity)
        state, task_id = receipt["state"], receipt["task_id"]
        if state == "succeeded":
            return True
        if state == "submitting":
            raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Search submission requires reconciliation", 503)
        if state == "prepared":
            self.store.mark_submitting(claim, **identity)
            # Timeout/accepted-but-not-persisted leaves durable submitting.
            # Never retry this call automatically, even after a new lease.
            task_id = self.client.replace_documents(frozen) if operation == "replace" else self.client.delete_documents(frozen)
            self.store.record_task(claim, task_id=task_id, **identity)
        elif state != "submitted":
            raise ContractError("SEARCH_TASK_CONFLICT", "Search task state is invalid", 409)
        status = self.client.task_status(task_id, task_type="documentAdditionOrUpdate" if operation == "replace" else "documentDeletion")
        if status in ("failed", "canceled"):
            raise ContractError("SEARCH_TASK_FAILED", "Search task requires recovery", 503)
        if status != "succeeded":
            return False
        self.store.record_succeeded(claim, **identity)
        return True
