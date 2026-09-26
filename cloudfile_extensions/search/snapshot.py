"""Private index snapshot adapter, not user content access authorization.

Native lifecycle_scope must hold the real structure/lifecycle guard for the
whole read. Deployment cannot replace it with an earlier boolean/RPC preflight.
"""
from ..common.errors import ContractError
from ..resources.paths import resource_ref
from ..resources.store import ResourceStore
from ..tags.read import bound_tags


class IndexSnapshotReader:
    def __init__(self, store, *, lifecycle_scope):
        if not isinstance(store, ResourceStore) or not callable(lifecycle_scope):
            raise ValueError("actual sparse resource store and protected native lifecycle scope required")
        self.store, self.lifecycle_scope = store, lifecycle_scope

    def __call__(self, cursor, reference):
        if getattr(cursor, "connection", None) is not self.store.connection:
            raise ValueError("same owned SQL connection required")
        ref = resource_ref(reference)
        # Verify the caller really owns an SQL transaction, without beginning or
        # committing one on its behalf. The store's locking lookup uses this conn.
        from uuid import uuid4
        savepoint = "cf_search_" + uuid4().hex
        try:
            cursor.execute("SAVEPOINT " + savepoint)
            cursor.execute("RELEASE SAVEPOINT " + savepoint)
        except Exception:
            raise ContractError("SEARCH_PROJECTION_PENDING", "Owned index transaction is unavailable", 503) from None
        with self.lifecycle_scope(cursor, ref) as raw_evidence:
            evidence = self.store._validate_evidence(raw_evidence)
            row = self.store._row(ref, evidence, locking=True)
            snapshot = self.store._snapshot(ref, evidence, row)
            snapshot["tags"] = bound_tags(cursor, resource_uid=row["uid"], repo_id=ref["repo_id"]) if row else []
            # No access/read/write grant: the query side uses its own actual user
            # ResourceService and never trusts an indexer's privilege or snapshot.
            return snapshot
