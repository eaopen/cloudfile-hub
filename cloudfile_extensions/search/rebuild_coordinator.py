"""One protected directory page or one existing task; no worker activation."""
import json
import time

from ..common.errors import ContractError
from .documents import resource_document
from .native_directory import NativeCommitDirectoryReader
from .rebuild_execution import SearchRebuildExecution
from .source import OwnedIndexSource


class SearchRebuildCoordinator:
    def __init__(self, execution, reader, source, *, clock=time.monotonic):
        if (not isinstance(execution, SearchRebuildExecution) or not isinstance(reader, NativeCommitDirectoryReader) or
                not isinstance(source, OwnedIndexSource) or source.worker_connection is not execution.store.connection or
                not callable(clock)):
            raise ValueError("actual rebuild execution, protected native reader and owned source required")
        self.execution, self.reader, self.source, self.clock = execution, reader, source, clock

    def advance(self, *, generation, repo_id):
        value = self.execution.advance_next(generation=generation, repo_id=repo_id)
        if value["state"] != "needs_page":
            return value
        ref = value["reference"]
        deadline, documents = self.clock() + 20, []
        # Hold the commit/library guard until sparse SQL reads are rolled back.
        # The real provider must reject lifecycle/commit drift, not merely pin
        # historical directory blobs while permitting current objects to move.
        with self.reader.read_page(repo_id=repo_id, commit_id=value["commit_id"], path=ref["path"], offset=value["offset"], limit=100) as page:
            with self.source.scope(repo_id) as cursor:
                for child in page["items"]:
                    if self.clock() >= deadline:
                        raise ContractError("SEARCH_REBUILD_PENDING", "Rebuild projection deadline exceeded", 503)
                    snapshot = self.source.read(cursor, child)
                    documents.append(resource_document(child, source_sequence=value["source_sequence"], annotation=snapshot))
                    raw = json.dumps(documents, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
                    if len(raw) > 1048576:
                        raise ContractError("SEARCH_REBUILD_PENDING", "Rebuild page exceeds byte budget", 503)
            if self.clock() >= deadline:
                raise ContractError("SEARCH_REBUILD_PENDING", "Rebuild projection deadline exceeded", 503)
        # All projections succeeded. Freeze after native/SQL source scopes close;
        # later incremental events must be replayed before index publication.
        self.execution.store.freeze(generation=generation, index=self.execution.client.index, repo_id=repo_id,
            path=ref["path"], offset=value["offset"], next_offset=page["next_offset"], documents=documents)
        return {**value, "state": "page_frozen"}
