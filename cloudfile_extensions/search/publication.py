"""Explicit publication under native and global producer barriers; no activation."""
from uuid import UUID, uuid4

from ..common.errors import ContractError
from ..common.validation import sequence
from .rebuild_store import SearchRebuildStore
from .tasks import MeilisearchTasks


class SearchPublication:
    def __init__(self, store, client, *, producer_scope, global_producer_scope):
        if (not isinstance(store, SearchRebuildStore) or not isinstance(client, MeilisearchTasks) or
                not callable(producer_scope) or not callable(global_producer_scope)):
            raise ValueError("actual publication store/client and producer barriers required")
        self.store, self.client = store, client
        self.producer_scope, self.global_producer_scope = producer_scope, global_producer_scope

    @staticmethod
    def _checkpoint(sql, generation, repo_id, baseline):
        table = "cf_search_global_catchup" if repo_id is None else "cf_search_catchup"
        where = "generation=%s" if repo_id is None else "generation=%s AND repo_id=%s"
        key = (generation,) if repo_id is None else (generation, repo_id)
        sql.execute("SELECT baseline,target_sequence,checked_sequence,state FROM " + table + " WHERE " + where + " FOR UPDATE", key)
        row = sql.fetchone()
        if (row is None or len(row) != 4 or any(type(v) is not int for v in row[:3]) or
                row[0] != baseline or not baseline <= row[1] <= 2 ** 64 - 1 or
                row[2] != row[1] or row[3] != "complete"):
            raise ContractError("SEARCH_CATCHUP_PENDING", "Complete publication checkpoint required", 409)
        stream = "security" if repo_id is None else "repo." + repo_id
        sql.execute("SELECT MAX(sequence) FROM cf_event_outbox FORCE INDEX(stream_sequence) WHERE stream=%s", (stream,))
        maximum = sql.fetchone()
        current = maximum[0] if maximum is not None and maximum[0] is not None else 0
        if type(current) is not int or current != row[1]:
            raise ContractError("SEARCH_CATCHUP_PENDING", "Producer boundary changed; refresh and catch up first", 409)

    def publish(self, *, generation, repo_id):
        ref, _ = self.store._directory(repo_id, "/")
        # Providers must drain native mutations AND their durable facts. Keep
        # both barriers until _owned commits; a preflight boolean is not a guard.
        with self.global_producer_scope(self.store.connection):
            with self.producer_scope(self.store.connection, ref["repo_id"]):
                with self.store._owned(generation, self.client.index) as sql:
                    sql.execute("SELECT source_sequence,state FROM cf_search_rebuild WHERE generation=%s AND repo_id=%s FOR UPDATE", (generation, ref["repo_id"]))
                    job = sql.fetchone()
                    if job is None or len(job) != 2 or job[1] != "scanned":
                        raise ContractError("SEARCH_REBUILD_PENDING", "Library scan is incomplete", 503)
                    baseline = sequence(job[0])
                    sql.execute("SELECT repo_id FROM cf_search_rebuild WHERE generation=%s AND state<>'scanned' LIMIT 1 FOR UPDATE", (generation,))
                    if sql.fetchone() is not None:
                        raise ContractError("SEARCH_REBUILD_PENDING", "Generation scans are incomplete", 503)
                    self._checkpoint(sql, generation, ref["repo_id"], baseline)
                    self._checkpoint(sql, generation, None, 0)
                    sql.execute("SELECT event_id FROM cf_search_task FORCE INDEX(generation_pending) WHERE index_generation=%s AND state IN ('submitting','submitted') LIMIT 1 FOR UPDATE", (generation,))
                    if sql.fetchone() is not None:
                        raise ContractError("SEARCH_TASK_PENDING", "Index writes are unresolved", 409)
                    self.client.require_configuration()
                    sql.execute("SELECT generation,revision FROM cf_search_publication WHERE repo_id=%s FOR UPDATE", (ref["repo_id"],))
                    previous = sql.fetchone()
                    if previous is not None:
                        try:
                            if len(previous) != 2 or str(UUID(previous[1])) != previous[1]:
                                raise ValueError()
                        except (ValueError, TypeError, AttributeError):
                            raise ContractError("SEARCH_PLAN_CONFLICT", "Invalid publication revision", 409) from None
                    revision = previous[1] if previous is not None and previous[0] == generation else str(uuid4())
                    if previous is None:
                        sql.execute("INSERT INTO cf_search_publication(repo_id,generation,revision,published_at) VALUES(%s,%s,%s,UTC_TIMESTAMP(6))", (ref["repo_id"], generation, revision))
                    elif previous[0] != generation:
                        sql.execute("UPDATE cf_search_publication SET generation=%s,revision=%s,published_at=UTC_TIMESTAMP(6) WHERE repo_id=%s", (generation, revision, ref["repo_id"]))
                    return dict(repo_id=ref["repo_id"], index_generation=generation, publication_revision=revision)
