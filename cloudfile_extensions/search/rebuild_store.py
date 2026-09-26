"""Persistent directory frontier and frozen pages, never a publication grant."""
import hashlib
import json
import re
from contextlib import contextmanager

from ..common.errors import ContractError
from ..common.validation import sequence
from ..resources.paths import resource_ref
from .documents import document_key
from .generations import SearchGenerationStore
from .initialization import SearchInitializationStore
from .meilisearch import _object


class SearchRebuildStore:
    FIELDS = "path,position,next_position,payload,payload_hash,state,task_id"
    def __init__(self, connection):
        self.connection = connection
        self.registry = SearchGenerationStore(connection)

    @contextmanager
    def _owned(self, generation, index):
        with self.registry._transaction() as sql:
            self.registry.require_dispatch(sql, generation, index)
            SearchInitializationStore(self.connection).require_complete(sql, generation, index)
            yield sql

    @staticmethod
    def _directory(repo_id, path):
        ref = resource_ref(dict(repo_id=repo_id, path=path, kind="dir"))
        raw = ref["path"].encode("utf-8")
        if len(raw) > 4096:
            raise ValueError("bounded rebuild directory required")
        return ref, hashlib.sha256(raw).hexdigest()

    def start(self, *, generation, index, repo_id, commit_id, source_sequence):
        ref, path_hash = self._directory(repo_id, "/")
        sequence(source_sequence)
        if not isinstance(commit_id, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_id):
            raise ValueError("fixed native commit required")
        with self._owned(generation, index) as sql:
            # Serialized with incremental intent/dispatch on the generation row.
            # Accepted or uncertain writes must finish/reconcile before scanning.
            sql.execute("SELECT event_id FROM cf_search_task FORCE INDEX(generation_pending) WHERE index_generation=%s AND state IN ('submitting','submitted') LIMIT 1 FOR UPDATE", (generation,))
            if sql.fetchone() is not None:
                raise ContractError("SEARCH_TASK_PENDING", "Existing index writes must finish before rebuilding", 409)
            # No outbox lock here: retain outbox→generation order used by workers.
            # Plan creation holds the generation lock too. This first consistent
            # read sees all plan commits preceding our acquisition of that lock.
            for table in ("cf_search_plan", "cf_search_fanout"):
                sql.execute("SELECT p.event_id FROM " + table + " p FORCE INDEX(generation_events) LEFT JOIN cf_event_outbox o ON o.event_id=p.event_id WHERE p.index_generation=%s AND (o.event_id IS NULL OR o.search_state<>'done') LIMIT 1", (generation,))
                if sql.fetchone() is not None:
                    raise ContractError("SEARCH_PLAN_PENDING", "Existing frozen search plans must finish before rebuilding", 409)
            sql.execute("INSERT INTO cf_search_rebuild(generation,repo_id,commit_id,source_sequence,state,updated_at) VALUES(%s,%s,%s,%s,'scanning',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE generation=generation", (generation, ref["repo_id"], commit_id, source_sequence))
            sql.execute("SELECT commit_id,source_sequence,state FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s FOR UPDATE", (generation, ref["repo_id"]))
            if sql.fetchone() != (commit_id, source_sequence, "scanning"):
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild snapshot identity changed", 409)
            sql.execute("INSERT INTO cf_search_rebuild_directory(generation,repo_id,path_hash,path,position,state,updated_at) VALUES(%s,%s,%s,'/',0,'ready',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE generation=generation", (generation, ref["repo_id"], path_hash))

    def freeze(self, *, generation, index, repo_id, path, offset, next_offset, documents):
        ref, path_hash = self._directory(repo_id, path)
        if (type(offset) is not int or not 0 <= offset <= 2 ** 31 - 102 or
                not isinstance(documents, list) or len(documents) > 100 or
                (next_offset is not None and (type(next_offset) is not int or len(documents) == 0 or next_offset != offset + len(documents)))):
            raise ValueError("bounded complete rebuild page required")
        seen = set()
        for document in documents:
            child = resource_ref({key: document[key] for key in ("repo_id", "path", "kind")})
            parent = child["path"].rsplit("/", 1)[0] or "/"
            if (child["repo_id"] != ref["repo_id"] or parent != ref["path"] or child["path"] in seen or
                    document.get("id") != document_key(child)):
                raise ValueError("unique immediate directory projections required")
            seen.add(child["path"])
        raw = json.dumps(documents, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        if len(raw.encode("utf-8")) > 1048576:
            raise ValueError("bounded frozen rebuild page required")
        digest = hashlib.sha256(b"cf.search.rebuild.page.v1\n" + index.encode("ascii") + b"\n" + raw.encode("utf-8")).hexdigest()
        with self._owned(generation, index) as sql:
            sql.execute("SELECT state FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s FOR UPDATE", (generation, ref["repo_id"]))
            if sql.fetchone() != ("scanning",):
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild is not scanning", 409)
            sql.execute("SELECT path,position,next_position,payload,payload_hash,state,task_id FROM cf_search_rebuild_directory WHERE generation=%s AND repo_id=%s AND path_hash=%s FOR UPDATE", (generation, ref["repo_id"], path_hash))
            row = sql.fetchone()
            if row is None or row[0] != ref["path"] or row[1] != offset:
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild directory position changed", 409)
            if row[5] == "pending":
                if row[2:5] != (next_offset, raw, digest):
                    raise ContractError("SEARCH_REBUILD_CONFLICT", "Frozen rebuild page changed", 409)
                return digest
            if row[5] != "ready" or any(row[position] is not None for position in (2, 3, 4, 6)):
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild directory is not ready", 409)
            sql.execute("UPDATE cf_search_rebuild_directory SET next_position=%s,payload=%s,payload_hash=%s,state='pending',updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND repo_id=%s AND path_hash=%s", (next_offset, raw, digest, generation, ref["repo_id"], path_hash))
            return digest

    def _page(self, sql, generation, index, ref, path_hash):
        sql.execute("SELECT " + self.FIELDS + " FROM cf_search_rebuild_directory WHERE generation=%s AND repo_id=%s AND path_hash=%s FOR UPDATE", (generation, ref["repo_id"], path_hash))
        row = sql.fetchone()
        try:
            if row is None or len(row) != 7 or row[0] != ref["path"] or type(row[1]) is not int or not 0 <= row[1] <= 2 ** 31 - 102:
                raise ValueError()
            value = dict(zip(self.FIELDS.split(","), row))
            if value["state"] not in ("pending", "submitting", "submitted"):
                raise ValueError()
            if not isinstance(value["payload"], str) or len(value["payload"].encode("utf-8")) > 1048576:
                raise ValueError()
            documents = json.loads(value["payload"], object_pairs_hook=_object)
            raw = json.dumps(documents, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(b"cf.search.rebuild.page.v1\n" + index.encode("ascii") + b"\n" + raw.encode("utf-8")).hexdigest()
            if not isinstance(documents, list) or len(documents) > 100 or raw != value["payload"] or digest != value["payload_hash"]:
                raise ValueError()
            if value["next_position"] is not None and (type(value["next_position"]) is not int or not documents or value["next_position"] != value["position"] + len(documents)):
                raise ValueError()
            seen = set()
            for document in documents:
                child = resource_ref({key: document[key] for key in ("repo_id", "path", "kind")})
                if (child["repo_id"] != ref["repo_id"] or (child["path"].rsplit("/", 1)[0] or "/") != ref["path"] or
                        child["path"] in seen or document["id"] != document_key(child)):
                    raise ValueError()
                seen.add(child["path"])
            task = value["task_id"]
            if ((value["state"] == "submitted" and (type(task) is not int or not 0 <= task <= 2 ** 63 - 1)) or
                    (value["state"] != "submitted" and task is not None)):
                raise ValueError()
            value["documents"] = documents
            return value
        except Exception:
            raise ContractError("SEARCH_REBUILD_CONFLICT", "Frozen rebuild page is invalid", 409) from None

    def load_page(self, *, generation, index, repo_id, path):
        ref, path_hash = self._directory(repo_id, path)
        with self._owned(generation, index) as sql:
            return self._page(sql, generation, index, ref, path_hash)

    def next_directory(self, *, generation, index, repo_id):
        """Bounded frontier lookup; scanned is not caught-up or published."""
        root, root_hash = self._directory(repo_id, "/")
        with self._owned(generation, index) as sql:
            sql.execute("SELECT commit_id,source_sequence,state FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s FOR UPDATE", (generation, root["repo_id"]))
            job = sql.fetchone()
            if (job is None or len(job) != 3 or not isinstance(job[0], str) or not re.fullmatch(r"[0-9a-f]{40}", job[0]) or
                    job[2] not in ("scanning", "scanned")):
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild snapshot is unavailable", 409)
            sequence(job[1])
            identity = dict(commit_id=job[0], source_sequence=job[1])
            # Equality on the existing composite index, one row per state.
            # Unknown dispatch stops this library rather than skipping to ready.
            for state in ("submitting", "submitted", "pending", "ready"):
                sql.execute("SELECT path_hash," + self.FIELDS + " FROM cf_search_rebuild_directory FORCE INDEX(pending_directories) WHERE generation=%s AND repo_id=%s AND state=%s ORDER BY path_hash LIMIT 1 FOR UPDATE", (generation, root["repo_id"], state))
                row = sql.fetchone()
                if row is None:
                    continue
                if job[2] != "scanning":
                    raise ContractError("SEARCH_REBUILD_CONFLICT", "Scanned rebuild has unfinished directories", 409)
                ref, path_hash = self._directory(repo_id, row[1])
                if path_hash != row[0]:
                    raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild directory identity changed", 409)
                if state == "ready":
                    if (row[6] != "ready" or type(row[2]) is not int or not 0 <= row[2] <= 2 ** 31 - 102 or
                            any(row[position] is not None for position in (3, 4, 5, 7))):
                        raise ContractError("SEARCH_REBUILD_CONFLICT", "Ready rebuild directory is invalid", 409)
                    return dict(**identity, reference=ref, state="ready", offset=row[2])
                page = self._page(sql, generation, index, ref, path_hash)
                return dict(**identity, reference=ref, state=page["state"], offset=page["position"])
            sql.execute("SELECT path_hash FROM cf_search_rebuild_directory WHERE generation=%s AND repo_id=%s AND state<>'done' LIMIT 1 FOR UPDATE", (generation, root["repo_id"]))
            if sql.fetchone() is not None:
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild directory state is invalid", 409)
            sql.execute("SELECT path,state,next_position,payload,payload_hash,task_id FROM cf_search_rebuild_directory WHERE generation=%s AND repo_id=%s AND path_hash=%s FOR UPDATE", (generation, root["repo_id"], root_hash))
            if sql.fetchone() != ("/", "done", None, None, None, None):
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild root is not complete", 409)
            if job[2] == "scanning":
                sql.execute("UPDATE cf_search_rebuild SET state='scanned',updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND repo_id=%s AND state='scanning'", (generation, root["repo_id"]))
            return dict(**identity, reference=None, state="scanned", offset=None)

    def mark_submitting(self, *, generation, index, repo_id, path, payload_hash):
        ref, path_hash = self._directory(repo_id, path)
        with self._owned(generation, index) as sql:
            page = self._page(sql, generation, index, ref, path_hash)
            if page["state"] != "pending" or page["payload_hash"] != payload_hash or not page["documents"]:
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild page intent is not current", 409)
            sql.execute("UPDATE cf_search_rebuild_directory SET state='submitting',updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND repo_id=%s AND path_hash=%s", (generation, ref["repo_id"], path_hash))

    def dispatch(self, *, generation, index, repo_id, path, payload_hash, send):
        ref, path_hash = self._directory(repo_id, path)
        if not callable(send):
            raise ValueError("bounded private rebuild dispatch required")
        with self._owned(generation, index) as sql:
            page = self._page(sql, generation, index, ref, path_hash)
            if page["state"] != "submitting" or page["payload_hash"] != payload_hash:
                raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild intent is not current", 409)
            task = send(page["documents"])
            if type(task) is not int or not 0 <= task <= 2 ** 63 - 1:
                raise ContractError("SEARCH_SUBMISSION_UNKNOWN", "Rebuild receipt is uncertain", 503)
            sql.execute("UPDATE cf_search_rebuild_directory SET state='submitted',task_id=%s,updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND repo_id=%s AND path_hash=%s", (task, generation, ref["repo_id"], path_hash))
            return task

    def complete_page(self, *, generation, index, repo_id, path, payload_hash, task_id):
        """Trusted executor has checked this exact remote task succeeded."""
        ref, path_hash = self._directory(repo_id, path)
        with self._owned(generation, index) as sql:
            page = self._page(sql, generation, index, ref, path_hash)
            empty = not page["documents"]
            if (page["payload_hash"] != payload_hash or
                    (empty and (page["state"] != "pending" or task_id is not None)) or
                    (not empty and (page["state"] != "submitted" or type(task_id) is not int or page["task_id"] != task_id))):
                raise ContractError("SEARCH_TASK_PENDING", "Rebuild page has not succeeded", 409)
            for document in page["documents"]:
                if document["kind"] != "dir":
                    continue
                child, child_hash = self._directory(repo_id, document["path"])
                sql.execute("INSERT INTO cf_search_rebuild_directory(generation,repo_id,path_hash,path,position,state,updated_at) VALUES(%s,%s,%s,%s,0,'ready',UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE generation=generation", (generation, ref["repo_id"], child_hash, child["path"]))
                sql.execute("SELECT path FROM cf_search_rebuild_directory WHERE generation=%s AND repo_id=%s AND path_hash=%s FOR UPDATE", (generation, ref["repo_id"], child_hash))
                if sql.fetchone() != (child["path"],):
                    raise ContractError("SEARCH_REBUILD_CONFLICT", "Rebuild directory hash collision", 409)
            next_position = page["next_position"]
            sql.execute("UPDATE cf_search_rebuild_directory SET position=%s,next_position=NULL,payload=NULL,payload_hash=NULL,task_id=NULL,state=%s,updated_at=UTC_TIMESTAMP(6) WHERE generation=%s AND repo_id=%s AND path_hash=%s", (next_position if next_position is not None else page["position"], "ready" if next_position is not None else "done", generation, ref["repo_id"], path_hash))
