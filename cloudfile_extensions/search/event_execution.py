"""One bounded advancement of an already frozen event; no worker registration."""
import json

from ..common.errors import ContractError
from .execution import SearchStepExecution, step_hash
from .plans import SearchPlanStore
from .tasks import MeilisearchTasks


class SearchEventExecution:
    def __init__(self, store, client):
        if not isinstance(store, SearchPlanStore) or not isinstance(client, MeilisearchTasks):
            raise ValueError("actual frozen plan store and private task client required")
        self.store, self.client = store, client
        self.steps = SearchStepExecution(store, client)

    def advance(self, claim, *, generation):
        plan = self.store.load(claim, generation=generation)
        if plan is None or plan["index"] != self.client.index:
            raise ContractError("SEARCH_PLAN_CONFLICT", "Frozen event plan is unavailable or has another index", 409)
        hashes = [step_hash(plan["index"], item["operation"], json.dumps(item["payload"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")) for item in plan["steps"]]
        receipts = {}
        for position, digest, state, task in self.store.progress(claim, generation=generation):
            if (type(position) is not int or not 0 <= position < len(hashes) or position in receipts or
                    digest != hashes[position] or state not in ("prepared", "submitting", "submitted", "succeeded") or
                    (state in ("submitted", "succeeded") and (type(task) is not int or not 0 <= task <= 2 ** 63 - 1)) or
                    (state in ("prepared", "submitting") and task is not None)):
                raise ContractError("SEARCH_PLAN_CONFLICT", "Search receipts disagree with frozen plan", 409)
            receipts[position] = state
        for position, item in enumerate(plan["steps"]):
            if receipts.get(position) != "succeeded":
                # Never dispatch a following delete/replace before this succeeds.
                self.steps.advance(claim, generation=generation, step=position,
                    operation=item["operation"], payload=item["payload"])
                return False
        self.store.complete_event(claim, generation=generation, payload_hashes=hashes)
        return True
