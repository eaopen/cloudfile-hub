"""CE14 managed-library guards on the same SQL connection as each read.

Until native byte facts are transactionally projected, a changed Branch head
requires a new generation. Never advertise the previous snapshot as current.
"""
from contextlib import contextmanager
from contextvars import ContextVar

from ..common.errors import ContractError
from ..jobs.authority import scope_locks
from ..resources.native import NativeResourceReader


class NativeSearchGuards:
    def __init__(self, *, provider, generation, lifecycle_reader, login_resources):
        if not callable(lifecycle_reader):
            raise ValueError("actual native lifecycle reader required")
        self.provider, self.generation = provider, generation
        self.reader, self.login_resources = lifecycle_reader, login_resources
        self.current = ContextVar("cloudfile_search_source", default=None)

    def scopes(self, repo=None, actor=None):
        result = [dict(type="provider", provider=self.provider, external_id=self.provider)]
        if actor is not None:
            result.append(dict(type="user", provider=self.provider, external_id=actor))
        if repo is not None:
            result.append(dict(type="repo", provider="cloudfile", external_id=repo))
        return result

    @staticmethod
    def head(sql, repo):
        sql.execute("SELECT repo_id FROM cf_managed_library WHERE repo_id=%s FOR UPDATE", (repo,))
        if sql.fetchone() != (repo,):
            raise ContractError("SEARCH_UNAVAILABLE", "Search requires a managed library", 503)
        sql.execute("SELECT commit_id FROM Branch WHERE repo_id=%s AND name='master' FOR UPDATE", (repo,))
        row = sql.fetchone()
        if row is None or not NativeResourceReader.commit_id(row[0]):
            raise ContractError("SEARCH_UNAVAILABLE", "Current native library is unavailable", 503)
        return row[0]

    @contextmanager
    def repo_scope(self, connection, repo):
        if self.current.get() is not None:
            raise ValueError("nested index source ownership is not supported")
        with scope_locks(connection, self.scopes(repo)):
            token = self.current.set((connection, repo))
            try:
                yield
            finally:
                self.current.reset(token)

    @contextmanager
    def lifecycle_scope(self, cursor, ref):
        if self.current.get() != (cursor.connection, ref["repo_id"]):
            raise ValueError("native reads require the same owned source connection")
        self.head(cursor, ref["repo_id"])
        yield self.reader(cursor, ref)

    @contextmanager
    def snapshot_scope(self, repo, commit):
        current = self.current.get()
        if current is None or current[1] != repo:
            raise ValueError("directory snapshots require an active owned SQL source")
        with current[0].cursor() as sql:
            if self.head(sql, repo) != commit:
                raise ContractError("SEARCH_REBUILD_PENDING", "Native snapshot changed; rebuild a new generation", 503)
            yield
            if self.head(sql, repo) != commit:
                raise ContractError("SEARCH_REBUILD_PENDING", "Native snapshot changed", 503)

    @contextmanager
    def capture_scope(self, connection, repo):
        with scope_locks(connection, self.scopes(repo)):
            # Named guards serialize supported managed native publications and
            # metadata producers across the transactions owned by the store.
            connection.begin()
            try:
                with connection.cursor() as sql:
                    head = self.head(sql, repo)
                    sql.execute("SELECT commit_id FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s", (self.generation, repo))
                    saved = sql.fetchone()
                    if saved is not None and saved != (head,):
                        raise ContractError("SEARCH_REBUILD_PENDING", "Native snapshot changed; rebuild a new generation", 503)
            finally:
                connection.rollback()
            yield

    @contextmanager
    def global_capture_scope(self, connection):
        with scope_locks(connection, self.scopes()):
            yield

    @contextmanager
    def response_scope(self, request, resources, repo):
        from ..identity.native_session import BACKEND, SESSION_REFERENCE_KEY
        from ..identity.session_index import OIDCSessionIndex
        from ..identity.session_delete import NativeDBSessionDelete
        from seahub.auth import BACKEND_SESSION_KEY
        authority = resources.read_authority
        connection = authority.state.connection
        key, reference = request.session.session_key, request.session.get(SESSION_REFERENCE_KEY)
        if request.session.get(BACKEND_SESSION_KEY) != BACKEND:
            raise ContractError("AUTHENTICATION_REQUIRED", "Native OIDC session is required", 401)
        oidc = self.login_resources.oidc
        index = OIDCSessionIndex(connection, issuer=oidc.issuer, client_id=oidc.client_id)
        deletion = NativeDBSessionDelete(index, identity_schema=self.login_resources.resources.identity_schema)
        # Take all scopes in native canonical order on the resource connection.
        # Holding an OIDC guard on another connection can invert native order.
        with scope_locks(connection, self.scopes(repo, authority.actor) + [index.scope]):
            def check():
                connection.begin()
                try:
                    with connection.cursor() as sql:
                        deletion.assert_current(sql, key, reference)
                        head = self.head(sql, repo)
                        sql.execute("SELECT commit_id,state FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s", (self.generation, repo))
                        if sql.fetchone() != (head, "scanned"):
                            raise ContractError("SEARCH_REBUILD_PENDING", "Native snapshot changed; rebuild a new generation", 503)
                finally:
                    connection.rollback()
            check()
            yield
            if (request.session.session_key != key or request.session.get(SESSION_REFERENCE_KEY) != reference
                    or request.session.get(BACKEND_SESSION_KEY) != BACKEND):
                raise ContractError("AUTHENTICATION_REQUIRED", "Native OIDC session changed", 401)
            check()
