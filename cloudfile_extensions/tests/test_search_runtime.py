from contextlib import nullcontext
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.consumer import SearchEventConsumer
from cloudfile_extensions.search.runtime import SearchConsumerFactory


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
