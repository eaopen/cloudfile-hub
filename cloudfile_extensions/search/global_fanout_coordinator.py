"""One global tag event/page per advancement, through shared durable receipts."""
from ..common.errors import ContractError
from ..common.validation import sequence
from ..events.outbox import EventClaim, normalize_event
from ..tags.definitions import uuid_value
from .fanout_execution import SearchFanoutExecution
from .global_fanout_projection import project_global_binding_page
from .source import OwnedIndexSource
from .tag_fanout import binding_cutoff


class GlobalTagFanoutCoordinator:
    def __init__(self, execution, source):
        if (not isinstance(execution, SearchFanoutExecution) or not isinstance(source, OwnedIndexSource) or
                source.worker_connection is not execution.store.connection):
            raise ValueError("actual shared fanout execution and independently owned source required")
        self.execution, self.source = execution, source

    def advance(self, claim, *, generation):
        if not isinstance(claim, EventClaim) or claim.consumer != "search":
            raise ValueError("actual search claim required")
        payload = claim.payload
        if (not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload["schema_version"] != 1 or
                payload.get("event_id") != claim.event_id or payload.get("stream") != "security"):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Invalid global tag event", 503)
        seq = payload.get("sequence")
        sequence(seq)
        fact = normalize_event({key: value for key, value in payload.items() if key not in {"schema_version", "stream", "sequence", "recorded_at"}})
        reason = fact.get("reason")
        if (fact["source"] != "hub" or fact["action"] != "tags.definition.updated" or fact["result"] != "succeeded" or
                fact.get("repo_id") is not None or not isinstance(reason, str) or not reason.startswith("tag_id:")):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Global tag event requires another planner", 503)
        tag, revision = uuid_value(reason[7:]), uuid_value(fact.get("revision"))
        store = self.execution.store
        value = store.load(claim, generation=generation)
        if value is None:
            with self.source.global_scope(tag, revision) as cursor:
                upper = binding_cutoff(cursor, tag_id=tag)
            store.start(claim, generation=generation, repo_id=None, tag_id=tag, revision=revision, upper_uid=upper)
            value = store.load(claim, generation=generation)
        if value is None or (value["repo_id"], value["tag_id"], value["tag_revision"]) != (None, tag, revision):
            raise ContractError("SEARCH_PLAN_CONFLICT", "Global tag scan identity changed", 409)
        if value["state"] == "scanned":
            store.complete_fanout(claim, generation=generation)
            return True
        if value["state"] == "ready":
            with self.source.global_scope(tag, revision) as cursor:
                page = project_global_binding_page(cursor, source=self.source, tag_id=tag, revision=revision,
                    upper_uid=value["upper_uid"], after=value["after_uid"], source_sequence=seq)
            store.freeze_page(claim, generation=generation, batch=value["batch"], after_uid=value["after_uid"],
                next_uid=page["next_uid"], index=self.execution.client.index, documents=page["documents"])
        self.execution.advance_pending(claim, generation=generation)
        return False
