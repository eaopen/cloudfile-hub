"""Resume one tag-definition event using durable bounded page state."""
from ..common.errors import ContractError
from ..common.validation import sequence
from ..events.outbox import EventClaim, normalize_event
from ..tags.definitions import decode, uuid_value
from ..tags.read import FIELDS
from .fanout_execution import SearchFanoutExecution
from .fanout_projection import project_binding_page
from .tag_fanout import binding_cutoff


class TagFanoutCoordinator:
    def __init__(self, execution, *, source_scope, snapshot_reader):
        if not isinstance(execution, SearchFanoutExecution) or not callable(source_scope) or not callable(snapshot_reader):
            raise ValueError("actual fanout executor and trusted owned native/SQL source required")
        self.execution, self.source_scope, self.snapshot_reader = execution, source_scope, snapshot_reader

    def advance(self, claim, *, generation):
        if not isinstance(claim, EventClaim) or claim.consumer != "search":
            raise ValueError("actual search event required")
        payload = claim.payload
        if (not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or
                payload["schema_version"] != 1 or payload.get("event_id") != claim.event_id):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Invalid tag event source", 503)
        sequence(payload.get("sequence"))
        event = normalize_event({key: value for key, value in payload.items() if key not in {"schema_version", "stream", "sequence", "recorded_at"}})
        reason = event.get("reason")
        if (event["source"] != "hub" or event["result"] != "succeeded" or event["action"] != "tags.definition.updated" or
                not event.get("repo_id") or payload.get("stream") != "repo." + event["repo_id"] or
                not isinstance(reason, str) or not reason.startswith("tag_id:")):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Tag event requires another planner", 503)
        tag, revision, repo = uuid_value(reason[7:]), uuid_value(event.get("revision")), event["repo_id"]
        store = self.execution.store
        value = store.load(claim, generation=generation)
        if value is None:
            with self.source_scope(repo, tag, revision) as cursor:
                cursor.execute("SELECT " + FIELDS + " FROM cf_tag WHERE tag_id=%s FOR UPDATE", (tag,))
                rows = cursor.fetchall()
                if len(rows) != 1:
                    raise ContractError("SEARCH_FANOUT_CHANGED", "Tag definition is unavailable", 409)
                definition = decode(rows[0])
                if definition["revision"] != revision or definition["scope_repo_id"] not in (None, repo):
                    raise ContractError("SEARCH_FANOUT_CHANGED", "Tag definition changed", 409)
                upper = binding_cutoff(cursor, tag_id=tag)
            store.start(claim, generation=generation, repo_id=repo, tag_id=tag, revision=revision, upper_uid=upper)
            value = store.load(claim, generation=generation)
        if value is None or (value["repo_id"], value["tag_id"], value["tag_revision"]) != (repo, tag, revision):
            raise ContractError("SEARCH_PLAN_CONFLICT", "Stored fanout does not match event", 409)
        if value["state"] == "scanned":
            store.complete_fanout(claim, generation=generation)
            return True
        if value["state"] == "ready":
            with self.source_scope(repo, tag, revision) as cursor:
                page = project_binding_page(cursor, repo_id=repo, tag_id=tag, revision=revision,
                    upper_uid=value["upper_uid"], after=value["after_uid"], source_sequence=payload["sequence"], snapshot_reader=self.snapshot_reader)
            store.freeze_page(claim, generation=generation, batch=value["batch"], after_uid=value["after_uid"],
                next_uid=page["next_uid"], index=self.execution.client.index, documents=page["documents"])
        self.execution.advance_pending(claim, generation=generation)
        # Final completion is a separate current-definition/lease SQL transaction.
        return False
