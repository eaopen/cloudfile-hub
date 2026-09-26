from contextlib import nullcontext
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.consumer import SearchEventConsumer
from cloudfile_extensions.search.runtime import SearchConsumerFactory, SearchInitializationFactory, SearchRebuildFactory, SearchRebuildRuntime
from cloudfile_extensions.search.initialization import SearchInitialization


class SearchRuntimeTest(TestCase):
    def setUp(self):
        self.connection = Mock()
        self.connection.get_autocommit.return_value = True
        self.options = dict(connection_factory=lambda: self.connection, repo_scope=lambda connection, repo: nullcontext(),
            lifecycle_scope=lambda cursor, ref: nullcontext(), resource_secret=b"s" * 32,
            endpoint="http://meilisearch:7700", index="resources", write_key="private", generation="generation", owner="worker")

    def test_real_component_assembly_does_not_run_consumer(self):
        with patch("cloudfile_extensions.search.runtime.SchemaRunner"):
            with SearchConsumerFactory(**self.options).open() as consumer:
                self.assertIsInstance(consumer, SearchEventConsumer)
                self.assertIs(consumer.outbox.connection, consumer.execution.store.connection)
                self.assertIs(consumer.outbox.connection, consumer.fanout.execution.store.connection)
                self.connection.begin.assert_not_called()
        self.connection.rollback.assert_called_once()
        self.connection.close.assert_called_once()

    def test_schema_failure_closes_owned_worker_connection(self):
        with patch("cloudfile_extensions.search.runtime.SchemaRunner") as runner:
            runner.return_value.require_current.side_effect = RuntimeError("schema mismatch")
            with self.assertRaises(RuntimeError):
                with SearchConsumerFactory(**self.options).open():
                    pass
        self.connection.close.assert_called_once()

    def test_missing_guard_cannot_assemble(self):
        with self.assertRaises(ValueError):
            SearchConsumerFactory(**{**self.options, "repo_scope": None})

    def test_nested_reused_connection_is_rejected_without_closing_outer_owner(self):
        factory = SearchConsumerFactory(**self.options)
        with patch("cloudfile_extensions.search.runtime.SchemaRunner"):
            with factory.open():
                with self.assertRaises(ContractError):
                    with factory.open():
                        pass
                self.connection.close.assert_not_called()
        self.connection.close.assert_called_once()

    def test_initialization_factory_assembles_without_registration_or_network(self):
        options = {key: self.options[key] for key in ("connection_factory", "endpoint", "index", "write_key", "generation")}
        factory = SearchInitializationFactory(**options)
        with patch("cloudfile_extensions.search.runtime.SchemaRunner"):
            with factory.open() as execution:
                self.assertIsInstance(execution, SearchInitialization)
                self.assertIs(execution.store.connection, self.connection)
                self.connection.begin.assert_not_called()
                with self.assertRaises(ContractError):
                    with factory.open():
                        pass
                self.connection.close.assert_not_called()
        self.connection.rollback.assert_called_once()
        self.connection.close.assert_called_once()

    def test_rebuild_factory_assembles_actual_owned_sources_without_running(self):
        options = {key: self.options[key] for key in ("connection_factory", "endpoint", "index", "write_key", "generation", "repo_scope", "lifecycle_scope", "resource_secret")}
        options["snapshot_scope"] = lambda repo, commit: nullcontext()
        options["capture_scope"] = lambda connection, repo: nullcontext()
        factory = SearchRebuildFactory(**options)
        with patch("cloudfile_extensions.search.runtime.SchemaRunner"):
            with factory.open() as runtime:
                self.assertIsInstance(runtime, SearchRebuildRuntime)
                self.assertEqual(runtime.generation, self.options["generation"])
                self.assertIs(runtime.coordinator.execution.store.connection, self.connection)
                self.assertIs(runtime.coordinator.source.worker_connection, self.connection)
                self.connection.begin.assert_not_called()
        self.connection.rollback.assert_called_once()
        self.connection.close.assert_called_once()
        with self.assertRaises(ValueError):
            SearchRebuildFactory(**{**options, "snapshot_scope": None})
