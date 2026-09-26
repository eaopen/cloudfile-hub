from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import EventClaim
from cloudfile_extensions.search.event_execution import SearchEventExecution
from cloudfile_extensions.search.plans import SearchPlanStore
from cloudfile_extensions.search.tasks import MeilisearchTasks


class SearchEventExecutionTest(TestCase):
    def setUp(self):
        self.store = Mock(spec=SearchPlanStore)
        self.client = Mock(spec=MeilisearchTasks)
        self.client.index = "resources"
        self.execution = SearchEventExecution(self.store, self.client)
        self.execution.steps = Mock()
        self.claim = EventClaim("event", "search", "worker", 1, {})

    def test_missing_plan_cannot_dispatch(self):
        self.store.load.return_value = None
        with self.assertRaises(ContractError):
            self.execution.advance(self.claim, generation="index")
        self.execution.steps.advance.assert_not_called()

    def test_only_first_pending_frozen_step_is_advanced(self):
        first = dict(operation="delete", payload=["a" * 64])
        self.store.load.return_value = dict(index="resources", steps=[first, dict(operation="delete", payload=["b" * 64])])
        self.store.progress.return_value = []
        self.assertFalse(self.execution.advance(self.claim, generation="index"))
        self.execution.steps.advance.assert_called_once_with(self.claim, generation="index", step=0, **first)
        self.store.complete_event.assert_not_called()

    def test_extra_receipt_is_not_ignored(self):
        self.store.load.return_value = dict(index="resources", steps=[dict(operation="delete", payload=["a" * 64])])
        self.store.progress.return_value = [(1, "x", "succeeded", 7)]
        with self.assertRaises(ContractError):
            self.execution.advance(self.claim, generation="index")
