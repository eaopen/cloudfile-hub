"""Durable, one-stage initialization; no rebuild or publication grant."""
import hashlib
import json
from contextlib import contextmanager

from ..common.errors import ContractError
from .documents import INDEX_SETTINGS
from .generations import SearchGenerationStore
from .tasks import MeilisearchTasks


def initialization_hash(index, stage):
    if stage not in ("create", "settings"):
        raise ValueError("fixed initialization stage required")
    payload = dict(uid=index, primaryKey="id") if stage == "create" else INDEX_SETTINGS
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(b"cf.search.initialize.v1\n" + index.encode("ascii") + b"\n" + stage.encode("ascii") + b"\n" + raw).hexdigest()


class SearchInitializationStore:
    def __init__(self, connection):
        self.registry = SearchGenerationStore(connection)
        self.connection = connection

    @contextmanager
    def _owned(self, generation, index):
        with self.registry._transaction() as sql:
            self.registry.require_dispatch(sql, generation, index)
            yield sql

    @staticmethod
    def _receipt(row, digest):
        if (row is None or row[0] != digest or row[1] not in ("prepared", "submitting", "submitted", "succeeded") or
                (row[1] in ("prepared", "submitting") and row[2] is not None) or
                (row[1] in ("submitted", "succeeded") and (type(row[2]) is not int or not 0 <= row[2] <= 2 ** 63 - 1))):
            raise ContractError("SEARCH_PLAN_CONFLICT", "Initialization receipt is invalid", 409)
        return dict(state=row[1], task_id=row[2])

    def prepare(self, generation, index, stage):
        digest = initialization_hash(index, stage)
        with self._owned(generation, index) as sql:
            if stage == "settings":
                sql.execute("SELECT payload_hash,state,task_id FROM cf_search_initialization WHERE generation=%s AND stage='create' FOR UPDATE", (generation,))
                previous = self._receipt(sql.fetchone(), initialization_hash(index, "create"))
                if previous["state"] != "succeeded":
                    raise ContractError("SEARCH_TASK_PENDING", "Index creation has not succeeded", 409)
            sql.execute("INSERT INTO cf_search_initialization(generation,stage,payload_hash,state,updated_at) VALUES(%s,%s,%s,'prepared',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE generation=generation", (generation, stage, digest))
            sql.execute("SELECT payload_hash,state,task_id FROM cf_search_initialization WHERE generation=%s AND stage=%s FOR UPDATE", (generation, stage))
            return self._receipt(sql.fetchone(), digest)

    def require_complete(self, sql, generation, index):
        """Caller retains generation lock and SQL transaction through dispatch."""
        if sql.connection is not self.connection:
            raise ValueError("owned initialization transaction required")
        for stage in ("create", "settings"):
            sql.execute("SELECT payload_hash,state,task_id FROM cf_search_initialization WHERE generation=%s AND stage=%s FOR UPDATE", (generation, stage))
            row = sql.fetchone()
            if row is None:
                raise ContractError("SEARCH_INITIALIZATION_PENDING", "Index initialization is incomplete", 503)
            if self._receipt(row, initialization_hash(index, stage))["state"] != "succeeded":
                raise ContractError("SEARCH_INITIALIZATION_PENDING", "Index initialization is incomplete", 503)

    def transition(self, generation, index, stage, previous, state, task_id=None):
        if (previous, state) not in (("prepared", "submitting"), ("submitted", "succeeded")) or task_id is not None:
            raise ValueError("fixed initialization transition required")
        digest = initialization_hash(index, stage)
        with self._owned(generation, index) as sql:
            sql.execute("UPDATE cf_search_initialization SET state=%s,updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND stage=%s AND payload_hash=%s AND state=%s", (state, generation, stage, digest, previous))
            if sql.rowcount != 1:
                raise ContractError("SEARCH_TASK_CONFLICT", "Initialization transition is not current", 409)

    def dispatch(self, generation, index, stage, send):
        digest = initialization_hash(index, stage)
        if not callable(send):
            raise ValueError("bounded initialization dispatch required")
        with self._owned(generation, index) as sql:
            sql.execute("SELECT payload_hash,state,task_id FROM cf_search_initialization WHERE generation=%s AND stage=%s FOR UPDATE", (generation, stage))
            receipt = self._receipt(sql.fetchone(), digest)
            if receipt != dict(state="submitting", task_id=None):
                raise ContractError("SEARCH_TASK_CONFLICT", "Initialization intent is not current", 409)
            task = send()
            if type(task) is not int or not 0 <= task <= 2 ** 63 - 1:
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Initialization submission is uncertain", 503)
            sql.execute("UPDATE cf_search_initialization SET state='submitted',task_id=%s,updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND stage=%s AND state='submitting'", (task, generation, stage))
            if sql.rowcount != 1:
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Initialization receipt could not be stored", 503)
            return task


class SearchInitialization:
    def __init__(self, store, client, *, generation):
        if not isinstance(store, SearchInitializationStore) or not isinstance(client, MeilisearchTasks):
            raise ValueError("actual initialization store and private client required")
        SearchGenerationStore._identity(generation, client.index)
        self.store, self.client, self.generation = store, client, generation

    def advance(self):
        for stage, task_type in (("create", "indexCreation"), ("settings", "settingsUpdate")):
            receipt = self.store.prepare(self.generation, self.client.index, stage)
            state, task = receipt["state"], receipt["task_id"]
            if state == "succeeded":
                continue
            if state == "submitting":
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Initialization requires reconciliation", 503)
            if state == "prepared":
                self.store.transition(self.generation, self.client.index, stage, "prepared", "submitting")
                send = self.client.create_index if stage == "create" else self.client.configure_index
                task = self.store.dispatch(self.generation, self.client.index, stage, send)
            status = self.client.task_status(task, task_type=task_type)
            if status in ("failed", "canceled"):
                raise ContractError("SEARCH_TASK_FAILED", "Initialization task did not succeed", 503)
            if status == "succeeded":
                self.store.transition(self.generation, self.client.index, stage, "submitted", "succeeded")
            # One asynchronous stage per call, even if it just succeeded.
            return False
        self.client.require_configuration()
        # Check retirement again after the network configuration read.
        if self.store.prepare(self.generation, self.client.index, "settings")["state"] != "succeeded":
            raise ContractError("SEARCH_TASK_PENDING", "Initialization is no longer complete", 409)
        return True
