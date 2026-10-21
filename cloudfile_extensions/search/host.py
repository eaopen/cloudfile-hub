"""Explicit process-owned search assembly; no threads or runtime DDL."""
from contextlib import contextmanager

from ..jobs.runtime import connect_database
from .configuration import validate_config
from .native_guards import NativeSearchGuards
from .query_runtime import SearchQueryFactory
from .runtime import SearchConsumerFactory, SearchInitializationFactory, SearchRebuildFactory


class SearchHost:
    def __init__(self, deployment, config, *, lifecycle_reader, resource_secret):
        value = validate_config(config)
        if deployment.resource_factory is None or deployment.login_resources is None:
            raise ValueError("actual resource and OIDC runtimes required")
        resources = deployment.factory.resources
        def connection():
            owned = connect_database(resources.environment)
            try:
                with owned.cursor() as sql:
                    sql.execute("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                return owned
            except Exception:
                owned.close()
                raise
        @contextmanager
        def redis_scope():
            yield resources.redis
        self.guards = NativeSearchGuards(provider=resources.provider, generation=value["generation"],
            lifecycle_reader=lifecycle_reader, login_resources=deployment.login_resources)
        base = dict(connection_factory=connection, endpoint=value["endpoint"], index=value["index"], generation=value["generation"])
        self.query = SearchQueryFactory(**base, resources=deployment.resource_factory, redis_scope=redis_scope,
            read_key=value["read_key"], cursor_secret=value["cursor_secret"],
            request_response_scope=self.guards.response_scope)
        self.initialize = SearchInitializationFactory(**base, write_key=value["write_key"])
        guards = dict(repo_scope=self.guards.repo_scope, lifecycle_scope=self.guards.lifecycle_scope,
            resource_secret=resource_secret)
        self.rebuild = SearchRebuildFactory(**base, **guards, write_key=value["write_key"],
            snapshot_scope=self.guards.snapshot_scope, capture_scope=self.guards.capture_scope,
            global_capture_scope=self.guards.global_capture_scope)
        self.consumer_options = dict(**base, **guards, write_key=value["write_key"])

    def capture_global_baseline(self):
        # Called only after durable initialization, before any repository scan.
        from .rebuild_store import SearchRebuildStore
        with self.initialize.open() as runtime:
            connection = runtime.store.connection
            with self.guards.global_capture_scope(connection):
                with SearchRebuildStore(connection)._owned(runtime.generation, runtime.client.index) as sql:
                    sql.execute("SELECT baseline FROM cf_search_global_catchup WHERE generation=%s FOR UPDATE", (runtime.generation,))
                    if sql.fetchone() is not None:
                        return
                    sql.execute("SELECT repo_id FROM cf_search_rebuild WHERE generation=%s LIMIT 1 FOR UPDATE", (runtime.generation,))
                    if sql.fetchone() is not None:
                        raise ValueError("global baseline must precede every repository scan")
                    sql.execute("SELECT COALESCE(MAX(sequence),0) FROM cf_event_outbox WHERE stream='security'")
                    boundary = sql.fetchone()[0]
                    sql.execute("INSERT INTO cf_search_global_catchup(generation,baseline,target_sequence,checked_sequence,state,updated_at) VALUES(%s,%s,%s,%s,'complete',UTC_TIMESTAMP(6))",
                        (runtime.generation, boundary, boundary, boundary))

    def consumer(self, owner):
        return SearchConsumerFactory(**self.consumer_options, owner=owner)
