"""Durable bounded tag pages; scanned is not authorization to ack the event."""
import json
import re

from ..common.errors import ContractError
from ..tags.definitions import uuid_value
from .execution import step_hash
from .task_store import SearchTaskStore


class SearchFanoutStore(SearchTaskStore):
    FIELDS = "repo_id,tag_id,tag_revision,upper_uid,after_uid,next_uid,batch,index_uid,payload,payload_hash,state"

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
            return None if row is None else dict(zip(self.FIELDS.split(","), row))

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
            sql.execute("SELECT batch,after_uid,upper_uid,state,index_uid,payload,payload_hash,next_uid FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            if row is None or row[0] != batch or row[1] != after_uid or row[3] not in ("ready", "pending"):
                raise ContractError("SEARCH_FANOUT_CHANGED", "Tag page position changed", 409)
            if next_uid is not None and (row[2] is None or not (after_uid or "") < next_uid <= row[2]):
                raise ValueError("tag page cursor exceeds captured scan")
            if row[3] == "pending":
                if tuple(row[4:]) != (index, raw.decode("utf-8"), digest, next_uid):
                    raise ContractError("SEARCH_PLAN_CONFLICT", "Frozen tag page changed", 409)
                return
            sql.execute("UPDATE cf_search_fanout SET state='pending',index_uid=%s,payload=%s,payload_hash=%s,next_uid=%s,updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s", (index, raw.decode("utf-8"), digest, next_uid, *key))

    def advance_page(self, claim, *, generation, batch):
        key = self._key(claim, generation, batch)[:2]
        with self._owned(claim) as sql:
            sql.execute("SELECT batch,next_uid,state,payload,payload_hash FROM cf_search_fanout WHERE event_id=%s AND index_generation=%s FOR UPDATE", key)
            row = sql.fetchone()
            if row is None or row[0] != batch or row[2] != "pending":
                raise ContractError("SEARCH_FANOUT_CHANGED", "Tag page is not current", 409)
            if row[3] != "[]":
                sql.execute("SELECT state,payload_hash,task_id FROM cf_search_task WHERE event_id=%s AND index_generation=%s AND step=%s FOR UPDATE", (*key, batch))
                task = sql.fetchone()
                if task is None or task[0] != "succeeded" or task[1] != row[4] or type(task[2]) is not int:
                    raise ContractError("SEARCH_TASK_PENDING", "Tag page index task is incomplete", 409)
            sql.execute("UPDATE cf_search_fanout SET after_uid=COALESCE(next_uid,upper_uid),next_uid=NULL,batch=batch+1,state=%s,index_uid=NULL,payload=NULL,payload_hash=NULL,updated_at=UTC_TIMESTAMP(6) WHERE event_id=%s AND index_generation=%s", ("ready" if row[1] is not None else "scanned", *key))
            return row[1] is None
