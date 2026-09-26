"""Persist immutable bounded event plans before any index network write."""
import hashlib
import json
import re

from ..common.errors import ContractError
from .meilisearch import _object
from .task_store import SearchTaskStore


def encode_plan(index, steps):
    if (not isinstance(index, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", index) or
            not isinstance(steps, list) or not 1 <= len(steps) <= 10001):
        raise ValueError("trusted bounded complete search plan required")
    for step in steps:
        if (not isinstance(step, dict) or set(step) != {"operation", "payload"} or step["operation"] not in ("replace", "delete") or
                not isinstance(step["payload"], list) or not 1 <= len(step["payload"]) <= 100):
            raise ValueError("bounded exact search steps required")
    raw = json.dumps(dict(index=index, steps=steps), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > 1048576:
        raise ValueError("search plan exceeds bounded event budget")
    return raw, hashlib.sha256(b"cf.search.plan.v1\n" + raw).hexdigest()


class SearchPlanStore(SearchTaskStore):
    def freeze(self, claim, *, generation, index, steps):
        self._key(claim, generation, 0)
        raw, digest = encode_plan(index, steps)
        with self._owned(claim) as sql:
            sql.execute("SELECT plan_hash,payload FROM cf_search_plan WHERE event_id=%s AND index_generation=%s FOR UPDATE", (claim.event_id, generation))
            previous = sql.fetchone()
            if previous is not None:
                if previous[0] != digest or previous[1] != raw.decode("utf-8"):
                    raise ContractError("SEARCH_PLAN_CONFLICT", "Search event plan changed", 409)
            else:
                sql.execute("INSERT INTO cf_search_plan(event_id,index_generation,plan_hash,payload,created_at) VALUES(%s,%s,%s,%s,UTC_TIMESTAMP(6))", (claim.event_id, generation, digest, raw.decode("utf-8")))
        return json.loads(raw.decode("utf-8"))

    def load(self, claim, *, generation):
        self._key(claim, generation, 0)
        with self._owned(claim) as sql:
            sql.execute("SELECT plan_hash,payload FROM cf_search_plan WHERE event_id=%s AND index_generation=%s FOR UPDATE", (claim.event_id, generation))
            row = sql.fetchone()
            if row is None:
                return None
            try:
                if not isinstance(row[1], str) or len(row[1].encode("utf-8")) > 1048576:
                    raise ValueError()
                plan = json.loads(row[1], object_pairs_hook=_object)
                if not isinstance(plan, dict) or set(plan) != {"index", "steps"}:
                    raise ValueError()
                raw, digest = encode_plan(plan["index"], plan["steps"])
                if row[0] != digest or row[1] != raw.decode("utf-8"):
                    raise ValueError()
            except (ValueError, TypeError, UnicodeError):
                raise ContractError("SEARCH_PLAN_CONFLICT", "Stored search event plan is invalid", 409) from None
            return plan
