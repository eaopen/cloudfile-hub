"""Advance only a previously frozen tag page; never ack the whole event."""
import json

from ..common.errors import ContractError
from .execution import SearchStepExecution
from .fanout_store import SearchFanoutStore
from .tasks import MeilisearchTasks


class SearchFanoutExecution:
    def __init__(self, store, client):
        if not isinstance(store, SearchFanoutStore) or not isinstance(client, MeilisearchTasks):
            raise ValueError("actual durable fanout store and private task client required")
        self.store, self.client = store, client
        self.steps = SearchStepExecution(store, client)

    def advance_pending(self, claim, *, generation):
        value = self.store.load(claim, generation=generation)
        if value is None:
            raise ContractError("SEARCH_PROJECTION_PENDING", "Tag fanout has not been prepared", 503)
        if value["state"] == "scanned":
            return "scanned"
        if value["state"] == "ready":
            return "needs_page"
        if value["index_uid"] != self.client.index:
            raise ContractError("SEARCH_PLAN_CONFLICT", "Tag page belongs to another index", 409)
        documents = json.loads(value["payload"])
        if documents and not self.steps.advance(claim, generation=generation, step=value["batch"], operation="replace", payload=documents):
            return "pending"
        scanned = self.store.advance_page(claim, generation=generation, batch=value["batch"])
        return "scanned" if scanned else "page_completed"
