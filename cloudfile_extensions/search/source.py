"""Owned read-only index source scopes; never installs a worker or HTTP route."""
from contextlib import contextmanager
from threading import Lock

from ..common.errors import ContractError
from ..resources.paths import resource_ref, normalize_path
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
    def scope(self, repo_id, tag_id=None, revision=None):
        uuid_value(repo_id)
        if (tag_id is None) != (revision is None):
            raise ValueError("complete optional tag source identity required")
        if tag_id is not None:
            uuid_value(tag_id)
            uuid_value(revision)
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

    @contextmanager
    def global_scope(self, tag_id, revision):
        """Fresh definition-locked SQL source, not a cross-library user grant."""
        uuid_value(tag_id)
        uuid_value(revision)
        connection = self.connection_factory()
        with self._lock:
            if connection is self.worker_connection or id(connection) in self._connections:
                raise ContractError("SEARCH_PROJECTION_PENDING", "Global source connection is already owned", 503)
            self._connections.add(id(connection))
        try:
            if not connection.get_autocommit():
                raise ContractError("SEARCH_PROJECTION_PENDING", "Clean global source connection required", 503)
            SchemaRunner(connection).require_current()
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT revision,kind,scope_repo_id FROM cf_tag WHERE tag_id=%s FOR UPDATE", (tag_id,))
                    if cursor.fetchone() != (revision, "system", None):
                        raise ContractError("SEARCH_FANOUT_CHANGED", "Global tag definition changed", 409)
                    yield cursor
            finally:
                connection.rollback()
        finally:
            try:
                connection.close()
            finally:
                with self._lock:
                    self._connections.discard(id(connection))

    def read_attribute(self, repo_id, path):
        """Exact existing sparse location, then actual native lifecycle validation.

        Annotation events already name a sparse UID. An absent/ambiguous row is
        a reconciliation condition, not permission to allocate or guess kind.
        """
        uuid_value(repo_id)
        path = normalize_path(path, "dir")
        try:
            if len(path.encode("utf-8")) > 4096:
                raise ValueError()
        except (UnicodeError, ValueError):
            raise ContractError("SEARCH_PROJECTION_PENDING", "Invalid annotation event path", 503) from None
        with self.scope(repo_id) as cursor:
            ResourceStore._storage(cursor)
            cursor.execute("SELECT kind,path FROM cf_resource FORCE INDEX(resource_location) WHERE repo_id=%s AND path_hash=%s AND state='active' ORDER BY kind LIMIT 2 FOR UPDATE", (repo_id, ResourceStore._hash(path)))
            rows = cursor.fetchall()
            if len(rows) != 1 or len(rows[0]) != 2 or rows[0][1] != path or rows[0][0] not in ("file", "dir"):
                raise ContractError("SEARCH_PROJECTION_PENDING", "Annotation event location requires reconciliation", 503)
            return self.read(cursor, dict(repo_id=repo_id, path=path, kind=rows[0][0]))
