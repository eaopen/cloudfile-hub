"""Durable bounded tag pages; scanned is not authorization to ack the event."""
import json
import re

from ..common.errors import ContractError
from ..tags.definitions import uuid_value
from .execution import step_hash
from .meilisearch import _object
from .task_store import SearchTaskStore
from .fanout_receipts import fanout_pages_complete
from ..events.outbox import normalize_event


class SearchFanoutStore(SearchTaskStore):
    FIELDS = "repo_id,tag_id,tag_revision,upper_uid,after_uid,next_uid,batch,index_uid,payload,payload_hash,state"

    @classmethod
    def decode(cls, row):
        try:
            if len(row) != len(cls.FIELDS.split(",")):
                raise ValueError()
            value = dict(zip(cls.FIELDS.split(","), row))
            if value["repo_id"] is not None:
                uuid_value(value["repo_id"])
            for name in ("tag_id", "tag_revision"):
                uuid_value(value[name])
            for name in ("upper_uid", "after_uid", "next_uid"):
                if value[name] is not None:
                    uuid_value(value[name])
            upper, after, next_uid = value["upper_uid"], value["after_uid"], value["next_uid"]
            if (type(value["batch"]) is not int or not 0 <= value["batch"] <= 10001 or
                    value["state"] not in ("ready", "pending", "scanned") or
                    (after is not None and (upper is None or after > upper)) or
                    (next_uid is not None and (upper is None or not (after or "") < next_uid <= upper))):
                raise ValueError()
            if value["state"] == "pending":
                if (upper is None or value["batch"] > 10000 or not isinstance(value["index_uid"], str) or
                        not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["index_uid"]) or
                        not isinstance(value["payload"], str) or len(value["payload"].encode("utf-8")) > 1048576):
                    raise ValueError()
                documents = json.loads(value["payload"], object_pairs_hook=_object)
                if not isinstance(documents, list) or len(documents) > 100:
                    raise ValueError()
                raw = json.dumps(documents, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
                if value["payload"] != raw.decode("utf-8") or value["payload_hash"] != step_hash(value["index_uid"], "replace", raw):
                    raise ValueError()
            else:
                if any(value[name] is not None for name in ("next_uid", "index_uid", "payload", "payload_hash")):
                    raise ValueError()
                if value["state"] == "scanned" and after != upper:
                    raise ValueError()
                if value["state"] == "ready" and (upper is None or after == upper or value["batch"] > 10000):
                    raise ValueError()
            return value
        except (ValueError, TypeError, UnicodeError, ContractError):
            raise ContractError("SEARCH_PLAN_CONFLICT", "Stored tag scan is invalid", 409) from None

    def start(self, claim, *, generation, repo_id, tag_id, revision, upper_uid):
        key = self._key(claim, generation, 0)[:2]
        if repo_id is not None:
            uuid_value(repo_id)
        for value in (tag_id, revision):
            uuid_value(value)
        if upper_uid is not None:
            uuid_value(upper_uid)
        with self._owned(claim) as sql:
            self._planning_gate(sql, claim, generation)
            if repo_id is None:
                self._global_event(sql, claim, tag_id, revision)
                sql.execute("SELECT revision,kind,scope_repo_id FROM cf_tag WHERE tag_id=%s FOR UPDATE", (tag_id,))
                if sql.fetchone() != (revision, "system", None):
                    raise ContractError("SEARCH_FANOUT_CHANGED", "Global tag definition changed", 409)
            sql.execute("SELECT repo_id,tag_id,tag_revision,upper_uid FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            identity = (repo_id, tag_id, revision, upper_uid)
            if row is not None:
                if tuple(row) != identity:
                    raise ContractError("SEARCH_FANOUT_CHANGED", "Frozen tag scan changed", 409)
                return
            sql.execute("INSERT INTO cf_search_fanout(event_id,index_generation,repo_id,tag_id,tag_revision,upper_uid,state,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))", (*key, *identity, "ready" if upper_uid else "scanned"))

    @staticmethod
    def _global_event(sql, claim, tag_id, revision):
        sql.execute("SELECT payload FROM cf_event_outbox WHERE event_id=%s FOR UPDATE", (claim.event_id,))
        row = sql.fetchone()
        try:
            if row is None or not isinstance(row[0], str) or len(row[0].encode("utf-8")) > 65536:
                raise ValueError()
            payload = json.loads(row[0], object_pairs_hook=_object)
            if (type(payload.get("schema_version")) is not int or payload["schema_version"] != 1 or
                    payload.get("event_id") != claim.event_id or payload.get("stream") != "security"):
                raise ValueError()
            fact = normalize_event({key: value for key, value in payload.items() if key not in {"schema_version", "stream", "sequence", "recorded_at"}})
            if (fact["source"] != "hub" or fact["action"] != "tags.definition.updated" or fact["result"] != "succeeded" or
                    fact.get("repo_id") is not None or fact.get("reason") != "tag_id:" + tag_id or fact.get("revision") != revision or
                    any(fact.get(key) for key in ("path", "target_path", "resource_uid", "resource_kind"))):
                raise ValueError()
        except Exception:
            raise ContractError("SEARCH_PLAN_CONFLICT", "Global tag scan requires its exact durable event", 409) from None

    def load(self, claim, *, generation):
        key = self._key(claim, generation, 0)[:2]
        with self._owned(claim) as sql:
            sql.execute("SELECT " + self.FIELDS + " FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            return None if row is None else self.decode(row)

    def freeze_page(self, claim, *, generation, batch, after_uid, next_uid, index, documents):
        key = self._key(claim, generation, batch)[:2]
        if after_uid is not None:
            uuid_value(after_uid)
        if next_uid is not None:
            uuid_value(next_uid)
        if (not isinstance(index, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", index) or
                not isinstance(documents, list) or len(documents) > 100):
            raise ValueError("bounded exact tag batch required")
        raw = json.dumps(documents, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(raw) > 1048576:
            raise ValueError("tag batch exceeds byte budget")
        digest = step_hash(index, "replace", raw)
        with self._owned(claim) as sql:
            self._planning_gate(sql, claim, generation, index)
            sql.execute("SELECT " + self.FIELDS + " FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            value = None if row is None else self.decode(row)
            if value is None or value["batch"] != batch or value["after_uid"] != after_uid or value["state"] not in ("ready", "pending"):
                raise ContractError("SEARCH_FANOUT_CHANGED", "Tag page position changed", 409)
            if next_uid is not None and (value["upper_uid"] is None or not (after_uid or "") < next_uid <= value["upper_uid"]):
                raise ValueError("tag page cursor exceeds captured scan")
            if value["state"] == "pending":
                if (value["index_uid"], value["payload"], value["payload_hash"], value["next_uid"]) != (index, raw.decode("utf-8"), digest, next_uid):
                    raise ContractError("SEARCH_PLAN_CONFLICT", "Frozen tag page changed", 409)
                return
            sql.execute("UPDATE cf_search_fanout SET state='pending',index_uid=%s,payload=%s,payload_hash=%s,next_uid=%s,updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s", (index, raw.decode("utf-8"), digest, next_uid, *key))

    def advance_page(self, claim, *, generation, batch):
        key = self._key(claim, generation, batch)[:2]
        with self._owned(claim) as sql:
            sql.execute("SELECT " + self.FIELDS + " FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            value = None if row is None else self.decode(row)
            if value is None or value["batch"] != batch or value["state"] != "pending":
                raise ContractError("SEARCH_FANOUT_CHANGED", "Tag page is not current", 409)
            task_id = None
            if value["payload"] != "[]":
                sql.execute("SELECT state,payload_hash,task_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s AND step=%s FOR UPDATE", (*key, batch))
                task = sql.fetchone()
                if task is None or task[0] != "succeeded" or task[1] != value["payload_hash"] or type(task[2]) is not int or not 0 <= task[2] <= 2 ** 63 - 1:
                    raise ContractError("SEARCH_TASK_PENDING", "Tag page index task is incomplete", 409)
                task_id = task[2]
            sql.execute("INSERT INTO cf_search_fanout_page(event_id,index_generation,batch,index_uid,payload_hash,empty_page,task_id,completed_at) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))", (*key, batch, value["index_uid"], value["payload_hash"], int(value["payload"] == "[]"), task_id))
            sql.execute("UPDATE cf_search_fanout SET after_uid=COALESCE(next_uid,upper_uid),next_uid=NULL,batch=batch+1,state=%s,index_uid=NULL,payload=NULL,payload_hash=NULL,updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s", ("ready" if value["next_uid"] is not None else "scanned", *key))
            return value["next_uid"] is None

    def complete_fanout(self, claim, *, generation):
        """Confirm scanned pages and current definition in one lease-fenced SQL tx.

        Index generation publication fencing remains the runtime's responsibility.
        This does not turn a superseded tag revision into a successful update.
        """
        key = self._key(claim, generation, 0)[:2]
        with self._owned(claim) as sql:
            sql.execute("SELECT " + self.FIELDS + " FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            value = None if row is None else self.decode(row)
            if value is None or value["state"] != "scanned":
                raise ContractError("SEARCH_TASK_PENDING", "Tag scan is incomplete", 409)
            self._planning_gate(sql, claim, generation)
            sql.execute("SELECT index_uid FROM cf_search_generation WHERE generation=%s FOR UPDATE", (generation,))
            index = sql.fetchone()[0]
            if not fanout_pages_complete(sql, event_id=claim.event_id, generation=generation, index=index, batches=value["batch"], locking=True):
                raise ContractError("SEARCH_TASK_PENDING", "Tag page receipts are incomplete", 409)
            if value["repo_id"] is None:
                self._global_event(sql, claim, value["tag_id"], value["tag_revision"])
            sql.execute("SELECT revision,scope_repo_id,kind FROM cf_tag WHERE tag_id=%s FOR UPDATE", (value["tag_id"],))
            definition = sql.fetchone()
            if (definition is None or definition[0] != value["tag_revision"] or definition[1] not in (None, value["repo_id"]) or
                    (value["repo_id"] is None and definition[2] != "system")):
                raise ContractError("SEARCH_FANOUT_CHANGED", "Tag definition changed before completion", 409)
            # Other generations may contain an uncertain dispatch. Never unblock
            # the stream while it could still publish stale index content.
            sql.execute("SELECT step FROM cf_search_task WHERE event_id=%s AND (state<>'succeeded' OR task_id IS NULL OR task_id>9223372036854775807 OR (index_generation=%s AND step>=%s)) LIMIT 1 FOR UPDATE", (*key, value["batch"]))
            if sql.fetchone() is not None:
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Tag index tasks require reconciliation", 503)
            sql.execute("UPDATE cf_event_outbox SET search_state='done',search_expiry=NULL,search_error=NULL WHERE event_id=%s AND search_state='running' AND search_owner=%s AND search_epoch=%s AND search_expiry>UTC_TIMESTAMP(6)", (claim.event_id, claim.owner, claim.epoch))
            if sql.rowcount != 1:
                raise ContractError("WORKER_LEASE_LOST", "Tag event lease expired before completion", 409)
