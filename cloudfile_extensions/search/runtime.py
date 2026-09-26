"""Explicit owned consumer assembly; no schedule, deployment or capability enable."""
from contextlib import contextmanager
from threading import Lock
import re

from ..common.errors import ContractError
from ..events.outbox import Outbox
from ..schema.runner import SchemaRunner
from .consumer import SearchEventConsumer
from .event_execution import SearchEventExecution
from .fanout_coordinator import TagFanoutCoordinator
from .fanout_execution import SearchFanoutExecution
from .fanout_store import SearchFanoutStore
from .plans import SearchPlanStore
from .projection import AttributeSearchProjection
from .source import OwnedIndexSource
from .tasks import MeilisearchTasks
from .initialization import SearchInitialization, SearchInitializationStore
from .generations import SearchGenerationStore
from .native_directory import NativeCommitDirectoryReader
from .rebuild_store import SearchRebuildStore
from .rebuild_execution import SearchRebuildExecution
from .rebuild_coordinator import SearchRebuildCoordinator
from .catchup import SearchCatchupInspector
from .global_fanout_coordinator import GlobalTagFanoutCoordinator


class SearchInitializationFactory:
    """Explicit private initialization assembly; no automatic registration/run."""
    def __init__(self, *, connection_factory, endpoint, index, write_key, generation):
        if not callable(connection_factory):
            raise ValueError("dedicated connection factory required")
        SearchGenerationStore._identity(generation, index)
        MeilisearchTasks(endpoint=endpoint, index=index, key=write_key)
        self.connection_factory = connection_factory
        self.endpoint, self.index, self.key, self.generation = endpoint, index, write_key, generation
        self._active, self._lock = set(), Lock()

    @contextmanager
    def open(self):
        connection = self.connection_factory()
        with self._lock:
            if id(connection) in self._active:
                raise ContractError("SEARCH_UNAVAILABLE", "Initialization connection is already owned", 503)
            self._active.add(id(connection))
        try:
            if not connection.get_autocommit():
                raise ContractError("SEARCH_UNAVAILABLE", "Clean initialization connection required", 503)
            SchemaRunner(connection).require_current()
            yield self._assemble(connection)
        finally:
            try:
                try:
                    connection.rollback()
                finally:
                    connection.close()
            finally:
                with self._lock:
                    self._active.discard(id(connection))

    def _assemble(self, connection):
        return SearchInitialization(SearchInitializationStore(connection),
            MeilisearchTasks(endpoint=self.endpoint, index=self.index, key=self.key), generation=self.generation)


class SearchRebuildRuntime:
    """Fixed trusted generation; callers cannot select another physical index."""
    def __init__(self, coordinator, *, generation, capture_scope):
        if not isinstance(coordinator, SearchRebuildCoordinator):
            raise ValueError("actual rebuild coordinator required")
        SearchGenerationStore._identity(generation, coordinator.execution.client.index)
        if not callable(capture_scope):
            raise ValueError("actual producer capture scope required")
        self.coordinator, self.generation = coordinator, generation
        self.capture_scope = capture_scope

    def start(self, *, repo_id):
        return self.coordinator.execution.store.capture_start(generation=self.generation,
            index=self.coordinator.execution.client.index, repo_id=repo_id,
            capture_scope=self.capture_scope)

    def advance(self, *, repo_id):
        return self.coordinator.advance(generation=self.generation, repo_id=repo_id)

    def advance_catchup(self, *, repo_id):
        return SearchCatchupInspector(self.coordinator.execution.store).advance_checkpoint(
            generation=self.generation, index=self.coordinator.execution.client.index, repo_id=repo_id)

    def refresh_catchup_target(self, *, repo_id):
        return SearchCatchupInspector(self.coordinator.execution.store).refresh_target(
            generation=self.generation, index=self.coordinator.execution.client.index, repo_id=repo_id,
            producer_scope=self.capture_scope)

    def advance_global_catchup(self):
        return SearchCatchupInspector(self.coordinator.execution.store).advance_global_checkpoint(
            generation=self.generation, index=self.coordinator.execution.client.index)


class SearchRebuildFactory(SearchInitializationFactory):
    """Owned rebuild assembly, sharing explicit connection cleanup, not jobs."""
    def __init__(self, *, connection_factory, endpoint, index, write_key, generation,
                 snapshot_scope, capture_scope, repo_scope, lifecycle_scope, resource_secret):
        if (not callable(snapshot_scope) or not callable(capture_scope) or not callable(repo_scope) or not callable(lifecycle_scope) or
                not isinstance(resource_secret, bytes) or len(resource_secret) < 32):
            raise ValueError("actual native snapshot/repo/lifecycle scopes and secret required")
        super().__init__(connection_factory=connection_factory, endpoint=endpoint, index=index,
            write_key=write_key, generation=generation)
        self.snapshot_scope, self.repo_scope, self.lifecycle_scope = snapshot_scope, repo_scope, lifecycle_scope
        self.capture_scope = capture_scope
        self.secret = resource_secret

    def _assemble(self, connection):
        client = MeilisearchTasks(endpoint=self.endpoint, index=self.index, key=self.key)
        source = OwnedIndexSource(connection_factory=self.connection_factory, worker_connection=connection,
            repo_scope=self.repo_scope, lifecycle_scope=self.lifecycle_scope, secret=self.secret)
        execution = SearchRebuildExecution(SearchRebuildStore(connection), client)
        coordinator = SearchRebuildCoordinator(execution,
            NativeCommitDirectoryReader(snapshot_scope=self.snapshot_scope), source)
        return SearchRebuildRuntime(coordinator, generation=self.generation, capture_scope=self.capture_scope)


class SearchConsumerFactory:
    def __init__(self, *, connection_factory, repo_scope, lifecycle_scope, resource_secret,
                 endpoint, index, write_key, generation, owner):
        if (not callable(connection_factory) or not callable(repo_scope) or not callable(lifecycle_scope) or
                not isinstance(resource_secret, bytes) or len(resource_secret) < 32 or
                not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", generation) or
                not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", owner)):
            raise ValueError("fixed owned search runtime and actual native guards required")
        # Configuration validation does not perform any network request.
        MeilisearchTasks(endpoint=endpoint, index=index, key=write_key)
        self.connection_factory, self.repo_scope, self.lifecycle_scope = connection_factory, repo_scope, lifecycle_scope
        self.secret, self.endpoint, self.index, self.key = resource_secret, endpoint, index, write_key
        self.generation, self.owner = generation, owner
        self._active, self._lock = set(), Lock()

    @contextmanager
    def open(self):
        connection = self.connection_factory()
        with self._lock:
            if id(connection) in self._active:
                raise ContractError("SEARCH_UNAVAILABLE", "Worker connection is already owned", 503)
            self._active.add(id(connection))
        try:
            if not connection.get_autocommit():
                raise ContractError("SEARCH_UNAVAILABLE", "Clean worker connection required", 503)
            SchemaRunner(connection).require_current()
            client = MeilisearchTasks(endpoint=self.endpoint, index=self.index, key=self.key)
            source = OwnedIndexSource(connection_factory=self.connection_factory, worker_connection=connection,
                repo_scope=self.repo_scope, lifecycle_scope=self.lifecycle_scope, secret=self.secret)
            execution = SearchEventExecution(SearchPlanStore(connection), client)
            fanout = TagFanoutCoordinator(SearchFanoutExecution(SearchFanoutStore(connection), client),
                source_scope=source.scope, snapshot_reader=source.read)
            global_fanout = GlobalTagFanoutCoordinator(SearchFanoutExecution(SearchFanoutStore(connection), client), source)
            yield SearchEventConsumer(Outbox(connection), execution,
                AttributeSearchProjection(snapshot_reader=source.read_attribute), owner=self.owner,
                generation=self.generation, fanout=fanout, global_fanout=global_fanout)
        finally:
            try:
                try:
                    connection.rollback()
                finally:
                    connection.close()
            finally:
                with self._lock:
                    self._active.discard(id(connection))
