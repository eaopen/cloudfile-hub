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
from .plans import encode_plan
from .execution import step_hash
from .fanout_store import SearchFanoutStore
from .fanout_receipts import fanout_pages_complete


def plan_receipts_complete(index, row, receipts):
    """Exact full immutable plan, never a selected subset of successful steps."""
    try:
        if len(row) != 2 or not isinstance(row[1], str) or len(row[1].encode("utf-8")) > 1048576:
            raise ValueError()
        plan = json.loads(row[1], object_pairs_hook=_object)
        if not isinstance(plan, dict) or set(plan) != {"index", "steps"} or plan["index"] != index:
            raise ValueError()
        raw, digest = encode_plan(plan["index"], plan["steps"])
        if digest != row[0] or raw.decode("utf-8") != row[1]:
            raise ValueError()
        hashes = [step_hash(index, step["operation"], json.dumps(step["payload"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")) for step in plan["steps"]]
        if len(receipts) != len(hashes):
            return False
        for position, receipt in enumerate(receipts):
            if (len(receipt) != 4 or type(receipt[0]) is not int or receipt[0] != position or
                    receipt[1] != hashes[position] or receipt[2] != "succeeded" or
                    type(receipt[3]) is not int or not 0 <= receipt[3] <= 2 ** 63 - 1):
                return False
        return True
    except Exception:
        raise ContractError("SEARCH_PLAN_CONFLICT", "Catch-up frozen plan is invalid", 409) from None


class SearchCatchupInspector:
    def __init__(self, store, *, clock=time.monotonic):
        if not isinstance(store, SearchRebuildStore) or not callable(clock):
            raise ValueError("actual owned rebuild store required")
        self.store, self.clock = store, clock

    def check_batch(self, *, generation, index, repo_id, after=None):
        return self._inspect(generation=generation, index=index, repo_id=repo_id, after=after, persist=False)

    def advance_checkpoint(self, *, generation, index, repo_id):
        # No caller position/target; resume only the durable database checkpoint.
        return self._inspect(generation=generation, index=index, repo_id=repo_id, persist=True)

    def _inspect(self, *, generation, index, repo_id, after=None, persist=False):
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
            if persist:
                sql.execute("SELECT baseline,target_sequence,checked_sequence,state FROM cf_search_catchup WHERE generation=%s AND repo_id=%s FOR UPDATE", (generation, ref["repo_id"]))
                checkpoint = sql.fetchone()
                if checkpoint is None:
                    sql.execute("INSERT INTO cf_search_catchup(generation,repo_id,baseline,target_sequence,checked_sequence,state,updated_at) VALUES(%s,%s,%s,%s,%s,'pending',UTC_TIMESTAMP(6))", (generation, ref["repo_id"], baseline, target, baseline))
                else:
                    if (len(checkpoint) != 4 or any(type(value) is not int for value in checkpoint[:3]) or
                            checkpoint[0] != baseline or not baseline <= checkpoint[2] <= checkpoint[1] <= target or
                            checkpoint[3] not in ("pending", "complete") or
                            (checkpoint[3] == "complete" and checkpoint[2] != checkpoint[1])):
                        raise ContractError("SEARCH_PLAN_CONFLICT", "Catch-up checkpoint is invalid", 409)
                    target, position = checkpoint[1], checkpoint[2]
            def finish(state, checked, pending=None):
                if persist:
                    sql.execute("UPDATE cf_search_catchup SET checked_sequence=%s,state=%s,updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND repo_id=%s AND baseline=%s AND target_sequence=%s AND checked_sequence=%s", (checked, "complete" if checked == target else "pending", generation, ref["repo_id"], baseline, target, position))
                    # MySQL may report zero for an unchanged idempotent result.
                    if sql.rowcount not in (0, 1):
                        raise ContractError("SEARCH_PLAN_CONFLICT", "Catch-up checkpoint changed", 409)
                return dict(state=state, checked_through=str(checked), observed_cutoff=str(target), pending_event_id=pending)
            sql.execute("SELECT sequence,event_id,payload,search_state FROM cf_event_outbox FORCE INDEX(stream_sequence) WHERE stream=%s AND sequence>%s AND sequence<=%s ORDER BY sequence LIMIT 100", (stream, position, target))
            events = sql.fetchall()
            budget, plan_budget, checked = 0, 0, position
            for event_sequence, event_id, raw, state in events:
                if self.clock() >= deadline:
                    raise ContractError("SEARCH_UNAVAILABLE", "Catch-up check deadline exceeded", 503)
                try:
                    if type(event_sequence) is not int or not checked < event_sequence <= target or not isinstance(raw, str):
                        raise ValueError()
                    size = len(raw.encode("utf-8"))
                    if size > 65536:
                        raise ValueError()
                    if budget + size > 1048576:
                        return finish("batch_checked", checked)
                    budget += size
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
                    sql.execute("SELECT plan_hash,payload FROM cf_search_plan WHERE event_id=%s AND index_generation=%s", (event_id, generation))
                    plan = sql.fetchone()
                    sql.execute("SELECT " + SearchFanoutStore.FIELDS + " FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s", (event_id, generation))
                    fanout = sql.fetchone()
                    if plan is not None:
                        if fanout is not None:
                            raise ContractError("SEARCH_PLAN_CONFLICT", "Event has conflicting projection plans", 409)
                        size = len(plan[1].encode("utf-8")) if isinstance(plan[1], str) else 1048577
                        if size > 1048576:
                            raise ContractError("SEARCH_PLAN_CONFLICT", "Catch-up plan is unbounded", 409)
                        if plan_budget + size > 1048576:
                            return finish("batch_checked", checked)
                        plan_budget += size
                        sql.execute("SELECT step,payload_hash,state,task_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s ORDER BY step LIMIT 10002", (event_id, generation))
                        qualified = plan_receipts_complete(index, plan, sql.fetchall())
                    else:
                        value = None if fanout is None else SearchFanoutStore.decode(fanout)
                        qualified = value is not None and value["state"] == "scanned" and value["repo_id"] == ref["repo_id"]
                        if qualified:
                            qualified = fanout_pages_complete(sql, event_id=event_id, generation=generation, index=index, batches=value["batch"])
                    sql.execute("SELECT event_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s AND (state<>'succeeded' OR task_id IS NULL OR task_id>9223372036854775807) LIMIT 1", (event_id, generation))
                    qualified = qualified and sql.fetchone() is None
                    sql.execute("SELECT event_id FROM cf_search_task WHERE event_id=%s AND index_generation<>%s AND state<>'succeeded' LIMIT 1", (event_id, generation))
                    qualified = qualified and sql.fetchone() is None
                if not qualified:
                    return finish("event_pending", checked, event_id)
                checked = event_sequence
            if self.clock() >= deadline:
                raise ContractError("SEARCH_UNAVAILABLE", "Catch-up check deadline exceeded", 503)
            if not events and checked < target:
                raise ContractError("SEARCH_PLAN_CONFLICT", "Catch-up events disappeared", 409)
            return finish("batch_checked" if checked < target else "observed_cutoff_checked", checked)
