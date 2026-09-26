"""Advance one frozen rebuild page, never publish an index."""
from ..common.errors import ContractError
from .rebuild_store import SearchRebuildStore
from .tasks import MeilisearchTasks


class SearchRebuildExecution:
    def __init__(self, store, client):
        if not isinstance(store, SearchRebuildStore) or not isinstance(client, MeilisearchTasks):
            raise ValueError("actual rebuild store and private task client required")
        self.store, self.client = store, client

    def advance_next(self, *, generation, repo_id):
        value = self.store.next_directory(generation=generation, index=self.client.index, repo_id=repo_id)
        if value["state"] == "scanned":
            return value
        if value["state"] == "ready":
            # Caller must freeze actual protected native projections first.
            return {**value, "state": "needs_page"}
        completed = self.advance_page(generation=generation, repo_id=repo_id, path=value["reference"]["path"])
        return {**value, "state": "page_completed" if completed else "task_pending"}

    def advance_page(self, *, generation, repo_id, path):
        identity = dict(generation=generation, index=self.client.index, repo_id=repo_id, path=path)
        page = self.store.load_page(**identity)
        task = page["task_id"]
        if page["state"] == "submitting":
            raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Rebuild submission requires reconciliation", 503)
        if page["documents"]:
            if page["state"] == "pending":
                self.store.mark_submitting(**identity, payload_hash=page["payload_hash"])
                task = self.store.dispatch(**identity, payload_hash=page["payload_hash"], send=self.client.replace_documents)
            status = self.client.task_status(task, task_type="documentAdditionOrUpdate")
            if status in ("failed", "canceled"):
                raise ContractError("SEARCH_TASK_FAILED", "Rebuild task did not succeed", 503)
            if status != "succeeded":
                return False
        self.store.complete_page(**identity, payload_hash=page["payload_hash"], task_id=task)
        return True
