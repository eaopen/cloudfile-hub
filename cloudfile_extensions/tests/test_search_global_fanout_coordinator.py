from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import EventClaim
from cloudfile_extensions.search.fanout_execution import SearchFanoutExecution
from cloudfile_extensions.search.global_fanout_coordinator import GlobalTagFanoutCoordinator
from cloudfile_extensions.search.source import OwnedIndexSource


class GlobalFanoutCoordinatorTest(TestCase):
    def setUp(self):
        self.tag = "11111111-1111-4111-8111-111111111111"
        self.revision = "22222222-2222-4222-8222-222222222222"
        self.event = "33333333-3333-4333-8333-333333333333"
        self.execution = Mock(spec=SearchFanoutExecution)
        self.execution.store, self.execution.client = Mock(), Mock(index="resources")
        self.source = Mock(spec=OwnedIndexSource)
        self.source.worker_connection = self.execution.store.connection
        self.coordinator = GlobalTagFanoutCoordinator(self.execution, self.source)
        self.payload = dict(schema_version=1, event_id=self.event, stream="security", sequence="1", source="hub",
            action="tags.definition.updated", result="succeeded", occurred_at="2026-09-27T00:00:00Z",
            request_id="request", actor_user_id="provider", actor_kind="service", revision=self.revision, reason="tag_id:" + self.tag)
        self.claim = EventClaim(self.event, "search", "worker", 1, self.payload)
        self.value = dict(repo_id=None, tag_id=self.tag, tag_revision=self.revision, state="pending")
        self.execution.store.load.return_value = self.value

    def test_pending_page_resumes_without_enumeration(self):
        self.assertFalse(self.coordinator.advance(self.claim, generation="g1"))
        self.source.global_scope.assert_not_called()
        self.execution.advance_pending.assert_called_once_with(self.claim, generation="g1")
        self.execution.store.complete_fanout.assert_not_called()

    def test_scanned_global_event_uses_shared_atomic_completion(self):
        self.value["state"] = "scanned"
        self.assertTrue(self.coordinator.advance(self.claim, generation="g1"))
        self.execution.store.complete_fanout.assert_called_once_with(self.claim, generation="g1")
        self.execution.advance_pending.assert_not_called()

    def test_repo_event_cannot_enter_global_coordinator(self):
        self.payload["repo_id"] = self.tag
        with self.assertRaises(ContractError):
            self.coordinator.advance(self.claim, generation="g1")
        self.source.global_scope.assert_not_called()
