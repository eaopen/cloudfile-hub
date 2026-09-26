"""Initialization source regressions; no real index or deployment mutation."""
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.search.generations import SearchGenerationStore
from cloudfile_extensions.search.initialization import SearchInitialization, SearchInitializationStore
from cloudfile_extensions.search.tasks import MeilisearchTasks
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class InitializationExecutionTest(TestCase):
    def setUp(self):
        self.store = Mock(spec=SearchInitializationStore)
        self.client = Mock(spec=MeilisearchTasks)
        self.client.index = "resources_g1"
        self.execution = SearchInitialization(self.store, self.client, generation="g1")

    def test_unknown_submission_is_not_repeated(self):
        self.store.prepare.return_value = dict(state="submitting", task_id=None)
        with self.assertRaises(ContractError) as caught:
            self.execution.advance()
        self.assertEqual(caught.exception.code, "SEARCH_SUBMISSION_UNKNOWN")
        self.store.dispatch.assert_not_called()
        self.client.create_index.assert_not_called()

    def test_persisted_task_only_polls_one_stage(self):
        self.store.prepare.return_value = dict(state="submitted", task_id=7)
        self.client.task_status.return_value = "succeeded"
        self.assertFalse(self.execution.advance())
        self.client.task_status.assert_called_once_with(7, task_type="indexCreation")
        self.store.dispatch.assert_not_called()
        self.store.transition.assert_called_once_with("g1", "resources_g1", "create", "submitted", "succeeded")
        self.client.configure_index.assert_not_called()

    def test_completion_requires_current_configuration_and_durable_receipts(self):
        self.store.prepare.return_value = dict(state="succeeded", task_id=7)
        self.assertTrue(self.execution.advance())
        self.client.require_configuration.assert_called_once()
        self.store.dispatch.assert_not_called()


class InitializationSQLTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        SearchGenerationStore(self.connection).register("g1", "resources_g1")
        self.store = SearchInitializationStore(self.connection)

    def test_stage_order_and_unknown_dispatch_are_durable(self):
        with self.assertRaises(ContractError):
            self.store.prepare("g1", "resources_g1", "settings")
        self.assertEqual(self.store.prepare("g1", "resources_g1", "create"), dict(state="prepared", task_id=None))
        self.store.transition("g1", "resources_g1", "create", "prepared", "submitting")
        send = Mock(side_effect=RuntimeError("uncertain"))
        with self.assertRaises(RuntimeError):
            self.store.dispatch("g1", "resources_g1", "create", send)
        self.assertEqual(self.store.prepare("g1", "resources_g1", "create"), dict(state="submitting", task_id=None))

    def test_exact_receipt_unlocks_settings_and_retirement_blocks_dispatch(self):
        self.store.prepare("g1", "resources_g1", "create")
        self.store.transition("g1", "resources_g1", "create", "prepared", "submitting")
        self.assertEqual(self.store.dispatch("g1", "resources_g1", "create", Mock(return_value=7)), 7)
        self.store.transition("g1", "resources_g1", "create", "submitted", "succeeded")
        self.assertEqual(self.store.prepare("g1", "resources_g1", "settings"), dict(state="prepared", task_id=None))
        self.store.transition("g1", "resources_g1", "settings", "prepared", "submitting")
        SearchGenerationStore(self.connection).retire("g1", "resources_g1")
        send = Mock(return_value=8)
        with self.assertRaises(ContractError):
            self.store.dispatch("g1", "resources_g1", "settings", send)
        send.assert_not_called()
