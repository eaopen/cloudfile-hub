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


class SearchRebuildStore:
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
