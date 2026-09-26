"""Fixed-index publication/version adapter, never an authorization decision."""
from uuid import UUID

from ..schema.runner import SchemaRunner
from .generations import SearchGenerationStore
from .meilisearch import unavailable
from .rebuild_store import SearchRebuildStore
from .policy_version import SearchPolicyVersionReader


class SearchPublicationReader:
    """Fresh SQL ownership; stale runtime configuration fails closed.

    The opaque index_generation token includes the publication revision so that
    switching away and back cannot revive old cursors. The physical index stays
    fixed in the backend; neither callers nor this reader choose another index.
    policy_reader must read current durable policy state, not request input.
    This adapter does not replace the final permission/response guard.
    """
    def __init__(self, *, connection_factory, generation, index, policy_reader=None):
        if policy_reader is None:
            policy_reader = SearchPolicyVersionReader(connection_factory)
        if not callable(connection_factory) or not callable(policy_reader):
            raise ValueError("fresh owned SQL and durable policy reader required")
        SearchGenerationStore._identity(generation, index)
        self.connection_factory, self.policy_reader = connection_factory, policy_reader
        self.generation, self.index = generation, index

    def __call__(self, repo_id):
        connection = None
        try:
            repo = str(UUID(repo_id))
            if repo != repo_id:
                raise ValueError()
            connection = self.connection_factory()
            if not connection.get_autocommit():
                # Do not roll back or close another owner's transaction.
                connection = None
                raise ValueError()
            SchemaRunner(connection).require_current()
            with SearchRebuildStore(connection)._owned(self.generation, self.index) as sql:
                # Same generation -> publication lock order as publishing.
                sql.execute("SELECT generation,revision FROM cf_search_publication WHERE repo_id=%s FOR UPDATE", (repo,))
                row = sql.fetchone()
                if (row is None or len(row) != 2 or row[0] != self.generation or
                        str(UUID(row[1])) != row[1]):
                    raise ValueError()
                token = self.generation + ":" + row[1]
            policy = self.policy_reader(repo)
            if not isinstance(policy, str) or not policy or len(policy) > 512:
                raise ValueError()
            return dict(policy_revision=policy, index_generation=token, ready=True)
        except Exception:
            raise unavailable() from None
        finally:
            if connection is not None:
                try:
                    connection.rollback()
                finally:
                    connection.close()
