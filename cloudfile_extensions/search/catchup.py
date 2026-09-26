"""Bounded catch-up diagnostics, not a durable publication authorization.

The observed cutoff is committed SQL visibility, not proof that every native
producer has published. Publication needs the real producer barrier and a
durable complete checkpoint, including the global security stream.
"""
import json
import time

from ..common.errors import ContractError
from ..common.validation import sequence
from ..events.outbox import normalize_event, projection_required
from .meilisearch import _object
from .rebuild_store import SearchRebuildStore


class SearchCatchupInspector:
    def __init__(self, store, *, clock=time.monotonic):
        if not isinstance(store, SearchRebuildStore) or not callable(clock):
            raise ValueError("actual owned rebuild store required")
        self.store, self.clock = store, clock

    def check_batch(self, *, generation, index, repo_id, after=None):
        ref, _ = self.store._directory(repo_id, "/")
        deadline = self.clock() + 20
        with self.store._owned(generation, index) as sql:
            sql.execute("SELECT source_sequence,state FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s FOR UPDATE", (generation, ref["repo_id"]))
            job = sql.fetchone()
            if job is None or job[1] != "scanned":
                raise ContractError("SEARCH_REBUILD_PENDING", "Library scan must finish before catch-up", 503)
            baseline = sequence(job[0])
            position = baseline if after is None else sequence(after)
            if position < baseline:
                raise ValueError("catch-up position must follow rebuild boundary")
            stream = "repo." + ref["repo_id"]
            sql.execute("SELECT MAX(sequence) FROM cf_event_outbox FORCE INDEX(stream_sequence) WHERE stream=%s", (stream,))
            row = sql.fetchone()
            target = row[0] if row is not None and row[0] is not None else 0
            if type(target) is not int or not baseline <= target <= 2 ** 64 - 1 or position > target:
                raise ContractError("SEARCH_PLAN_CONFLICT", "Catch-up event boundary is invalid", 409)
            sql.execute("SELECT sequence,event_id,payload,search_state FROM cf_event_outbox FORCE INDEX(stream_sequence) WHERE stream=%s AND sequence>%s AND sequence<=%s ORDER BY sequence LIMIT 100", (stream, position, target))
            events = sql.fetchall()
            budget, checked = 0, position
            for event_sequence, event_id, raw, state in events:
                if self.clock() >= deadline:
                    raise ContractError("SEARCH_UNAVAILABLE", "Catch-up check deadline exceeded", 503)
                try:
                    if type(event_sequence) is not int or not checked < event_sequence <= target or not isinstance(raw, str):
                        raise ValueError()
                    size = len(raw.encode("utf-8"))
                    budget += size
                    if size > 65536 or budget > 1048576:
                        raise ValueError()
                    payload = json.loads(raw, object_pairs_hook=_object)
                    if (type(payload.get("schema_version")) is not int or payload["schema_version"] != 1 or
                            payload.get("event_id") != event_id or payload.get("stream") != stream or payload.get("sequence") != str(event_sequence)):
                        raise ValueError()
                    fact = normalize_event({key: value for key, value in payload.items() if key not in {"schema_version", "stream", "sequence", "recorded_at"}})
                    if fact.get("repo_id") != ref["repo_id"]:
                        raise ValueError()
                except Exception:
                    raise ContractError("SEARCH_PLAN_CONFLICT", "Catch-up event is invalid", 409) from None
                qualified = state == "done"
                if qualified and projection_required(fact):
                    sql.execute("SELECT event_id FROM cf_search_plan WHERE event_id=%s AND index_generation=%s", (event_id, generation))
                    plan = sql.fetchone()
                    sql.execute("SELECT state FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s", (event_id, generation))
                    fanout = sql.fetchone()
                    qualified = plan is not None or fanout == ("scanned",)
                    sql.execute("SELECT event_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s AND (state<>'succeeded' OR task_id IS NULL OR task_id>9223372036854775807) LIMIT 1", (event_id, generation))
                    qualified = qualified and sql.fetchone() is None
                if not qualified:
                    return dict(state="event_pending", checked_through=str(checked), observed_cutoff=str(target), pending_event_id=event_id)
                checked = event_sequence
            if self.clock() >= deadline:
                raise ContractError("SEARCH_UNAVAILABLE", "Catch-up check deadline exceeded", 503)
            return dict(state="batch_checked" if checked < target else "observed_cutoff_checked",
                checked_through=str(checked), observed_cutoff=str(target), pending_event_id=None)
