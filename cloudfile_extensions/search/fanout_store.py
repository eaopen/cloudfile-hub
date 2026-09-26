"""Durable bounded tag pages; scanned is not authorization to ack the event."""
import json
import re

from ..common.errors import ContractError
from ..tags.definitions import uuid_value
from .execution import step_hash
from .meilisearch import _object
from .task_store import SearchTaskStore


class SearchFanoutStore(SearchTaskStore):
    FIELDS = "repo_id,tag_id,tag_revision,upper_uid,after_uid,next_uid,batch,index_uid,payload,payload_hash,state"

    @classmethod
    def decode(cls, row):
        try:
            if len(row) != len(cls.FIELDS.split(",")):
                raise ValueError()
            value = dict(zip(cls.FIELDS.split(","), row))
            for name in ("repo_id", "tag_id", "tag_revision"):
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
        for value in (repo_id, tag_id, revision):
            uuid_value(value)
        if upper_uid is not None:
            uuid_value(upper_uid)
        with self._owned(claim) as sql:
            sql.execute("SELECT repo_id,tag_id,tag_revision,upper_uid FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            identity = (repo_id, tag_id, revision, upper_uid)
            if row is not None:
                if tuple(row) != identity:
                    raise ContractError("SEARCH_FANOUT_CHANGED", "Frozen tag scan changed", 409)
                return
            sql.execute("INSERT INTO cf_search_fanout(event_id,index_generation,repo_id,tag_id,tag_revision,upper_uid,state,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))", (*key, *identity, "ready" if upper_uid else "scanned"))

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
            if value["payload"] != "[]":
                sql.execute("SELECT state,payload_hash,task_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s AND step=%s FOR UPDATE", (*key, batch))
                task = sql.fetchone()
                if task is None or task[0] != "succeeded" or task[1] != value["payload_hash"] or type(task[2]) is not int or not 0 <= task[2] <= 2 ** 63 - 1:
                    raise ContractError("SEARCH_TASK_PENDING", "Tag page index task is incomplete", 409)
            sql.execute("UPDATE cf_search_fanout SET after_uid=COALESCE(next_uid,upper_uid),next_uid=NULL,batch=batch+1,state=%s,index_uid=NULL,payload=NULL,payload_hash=NULL,updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s", ("ready" if value["next_uid"] is not None else "scanned", *key))
            return value["next_uid"] is None
