from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import Outbox, EventClaim
from cloudfile_extensions.search.consumer import SearchEventConsumer
from cloudfile_extensions.search.event_execution import SearchEventExecution
from cloudfile_extensions.search.projection import AttributeSearchProjection


class SearchConsumerTest(TestCase):
    def setUp(self):
        self.outbox = Mock(spec=Outbox)
        self.outbox.connection = object()
        self.execution = Mock(spec=SearchEventExecution)
        self.execution.store = Mock(connection=self.outbox.connection)
        self.execution.client = Mock(index="resources")
        self.projection = Mock(spec=AttributeSearchProjection)
        self.consumer = SearchEventConsumer(self.outbox, self.execution, self.projection, owner="worker", generation="generation")
        self.claim = EventClaim("event", "search", "worker", 1, {})
        self.outbox.claim.return_value = self.claim

    def test_existing_plan_is_not_reprojected_after_restart(self):
        self.execution.store.load.return_value = dict(index="resources", steps=[])
        self.execution.advance.return_value = False
        self.assertEqual(self.consumer.run_once(), "pending")
        self.projection.plan.assert_not_called()
        self.outbox.acknowledge.assert_not_called()
        self.outbox.retry_later.assert_called_once_with(self.claim, code="INDEX_TASK_PENDING", delay_seconds=2)

    def test_unknown_submission_blocks_success_and_requires_recovery(self):
        self.execution.advance.side_effect = ContractError("SEARCH_SUBMISSION_UNKNOWN", "unknown", 503)
        self.assertEqual(self.consumer.run_once(), "recovery_required")
        self.outbox.acknowledge.assert_not_called()
        self.outbox.retry_later.assert_not_called()
        self.outbox.require_recovery.assert_called_once_with(self.claim, code="SEARCH_SUBMISSION_UNKNOWN")

    def test_changed_fanout_is_parked_not_retried(self):
        self.execution.advance.side_effect = ContractError("SEARCH_FANOUT_CHANGED", "changed", 409)
        self.assertEqual(self.consumer.run_once(), "recovery_required")
        self.outbox.require_recovery.assert_called_once_with(self.claim, code="SEARCH_FANOUT_CHANGED")
        self.outbox.retry_later.assert_not_called()
        self.outbox.acknowledge.assert_not_called()

    def test_success_is_not_acknowledged_a_second_time(self):
        self.execution.advance.return_value = True
        self.assertEqual(self.consumer.run_once(), "completed")
        self.outbox.acknowledge.assert_not_called()
        self.outbox.retry_later.assert_not_called()
