"""Project current sparse attribute events through a trusted native reader.

Native byte mutations/tag-definition fanout need their own bounded planners;
unknown operations are never silently acknowledged as indexed.
"""
from ..common.errors import ContractError
from ..common.validation import sequence
from ..events.outbox import EventClaim, normalize_event
from ..resources.paths import normalize_path, resource_ref
from .documents import resource_document


class AttributeSearchProjection:
    def __init__(self, *, snapshot_reader):
        if not callable(snapshot_reader):
            raise ValueError("trusted native lifecycle/annotation reader required")
        self.snapshot_reader = snapshot_reader

    def plan(self, claim):
        if not isinstance(claim, EventClaim) or claim.consumer != "search":
            raise ValueError("actual search event claim required")
        payload = claim.payload
        if not isinstance(payload, dict) or payload.get("schema_version") != 1 or payload.get("event_id") != claim.event_id:
            raise ContractError("SEARCH_PROJECTION_PENDING", "Search event requires reconciliation", 503)
        seq = payload.get("sequence")
        sequence(seq)
        event = normalize_event({key: value for key, value in payload.items() if key not in {"schema_version", "stream", "sequence", "recorded_at"}})
        if (event["action"] != "resource.attributes.updated" or event["source"] != "hub" or event["result"] != "succeeded" or
                not event.get("repo_id") or not event.get("path") or not event.get("resource_uid") or payload.get("stream") != "repo." + event["repo_id"]):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Search operation requires another planner", 503)
        # Reader owns current native path/type/lifecycle and sparse annotation
        # coherence. It must not fabricate kind from a suffix or content hash.
        snapshot = self.snapshot_reader(event["repo_id"], event["path"])
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("resource"), dict):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Native search source is unavailable", 503)
        ref = resource_ref(snapshot["resource"])
        if (ref["repo_id"] != event["repo_id"] or ref["path"] != normalize_path(event["path"], ref["kind"]) or
                snapshot.get("uid") != event["resource_uid"]):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Native resource lifecycle changed", 503)
        # This is an exact resource annotation change, not a recursive rename.
        document = resource_document(ref, source_sequence=seq, annotation=snapshot)
        return [dict(operation="replace", payload=[document])]
