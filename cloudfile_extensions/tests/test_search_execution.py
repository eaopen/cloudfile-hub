from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import EventClaim
from cloudfile_extensions.search.execution import SearchStepExecution
from cloudfile_extensions.search.task_store import SearchTaskStore
from cloudfile_extensions.search.tasks import MeilisearchTasks


class SearchExecutionTest(TestCase):
    def setUp(self):
        self.store = Mock(spec=SearchTaskStore)
        self.client = Mock(spec=MeilisearchTasks)
        self.client.index = "resources"
        self.execution = SearchStepExecution(self.store, self.client)
        self.claim = EventClaim("event", "search", "worker", 1, {})
        self.options = dict(generation="generation", step=0, operation="delete", payload=["a" * 64])

    def test_unknown_submission_never_resends(self):
        self.store.prepare.return_value = dict(state="submitting", task_id=None)
        with self.assertRaises(ContractError) as caught:
            self.execution.advance(self.claim, **self.options)
        self.assertEqual(caught.exception.code, "SEARCH_SUBMISSION_UNKNOWN")
        self.client.delete_documents.assert_not_called()

    def test_existing_task_is_polled_not_dispatched_again(self):
        self.store.prepare.return_value = dict(state="submitted", task_id=7)
        self.client.task_status.return_value = "processing"
        self.assertFalse(self.execution.advance(self.claim, **self.options))
        self.client.delete_documents.assert_not_called()
        self.store.record_succeeded.assert_not_called()

    def test_success_is_persisted_only_after_task_succeeded(self):
        self.store.prepare.return_value = dict(state="prepared", task_id=None)
        self.client.delete_documents.return_value = 7
        self.client.task_status.return_value = "succeeded"
        self.assertTrue(self.execution.advance(self.claim, **self.options))
        self.store.mark_submitting.assert_called_once()
        self.store.record_task.assert_called_once()
        self.store.record_succeeded.assert_called_once()

    def test_network_failure_does_not_record_success(self):
        self.store.prepare.return_value = dict(state="prepared", task_id=None)
        self.client.delete_documents.side_effect = RuntimeError("uncertain")
        with self.assertRaises(RuntimeError):
            self.execution.advance(self.claim, **self.options)
        self.store.record_task.assert_not_called()
        self.store.record_succeeded.assert_not_called()
