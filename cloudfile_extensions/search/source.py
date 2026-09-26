"""Owned read-only index source scopes; never installs a worker or HTTP route."""
from contextlib import contextmanager
from threading import Lock

from ..common.errors import ContractError
from ..resources.paths import resource_ref
from ..resources.store import ResourceStore
from ..schema.runner import SchemaRunner
from ..tags.definitions import uuid_value
from .snapshot import IndexSnapshotReader


class OwnedIndexSource:
    def __init__(self, *, connection_factory, worker_connection, repo_scope, lifecycle_scope, secret):
        if (not callable(connection_factory) or not callable(repo_scope) or not callable(lifecycle_scope) or
                worker_connection is None or not isinstance(secret, bytes) or len(secret) < 32):
            raise ValueError("owned connections and actual native index guards required")
        self.connection_factory, self.worker_connection = connection_factory, worker_connection
        self.repo_scope, self.lifecycle_scope, self.secret = repo_scope, lifecycle_scope, secret
        self._connections, self._readers, self._lock = set(), {}, Lock()

    @contextmanager
    def scope(self, repo_id, tag_id, revision):
        for value in (repo_id, tag_id, revision):
            uuid_value(value)
        connection = self.connection_factory()
        with self._lock:
            if connection is self.worker_connection or id(connection) in self._connections:
                # Never close a connection owned by the worker/another source.
                raise ContractError("SEARCH_PROJECTION_PENDING", "Source connection is not independently owned", 503)
            self._connections.add(id(connection))
        try:
            if not connection.get_autocommit():
                raise ContractError("SEARCH_PROJECTION_PENDING", "Clean source connection required", 503)
            SchemaRunner(connection).require_current()
            def forbidden(*args, **kwargs):
                raise ContractError("ACCESS_DENIED", "Index source cannot use legacy resource writes", 403)
            store = ResourceStore(connection, inspector=forbidden, write_guard=forbidden,
                mutation_hook=forbidden, secret=self.secret)
            reader = IndexSnapshotReader(store, lifecycle_scope=self.lifecycle_scope)
            # Real repository guard must pin structure/lifecycle until rollback.
            with self.repo_scope(connection, repo_id):
                connection.begin()
                try:
                    with connection.cursor() as cursor:
                        with self._lock:
                            self._readers[id(cursor)] = (cursor, repo_id, reader)
                        try:
                            yield cursor
                        finally:
                            with self._lock:
                                self._readers.pop(id(cursor), None)
                finally:
                    connection.rollback()
        finally:
            try:
                connection.close()
            finally:
                with self._lock:
                    self._connections.discard(id(connection))

    def read(self, cursor, reference):
        ref = resource_ref(reference)
        with self._lock:
            entry = self._readers.get(id(cursor))
        if entry is None or entry[0] is not cursor or entry[1] != ref["repo_id"]:
            raise ContractError("SEARCH_PROJECTION_PENDING", "Owned source cursor is not active for this repository", 503)
        return entry[2](cursor, ref)
