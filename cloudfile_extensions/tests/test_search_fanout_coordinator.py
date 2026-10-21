from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.events.outbox import EventClaim
from cloudfile_extensions.search.fanout_coordinator import TagFanoutCoordinator
from cloudfile_extensions.search.fanout_execution import SearchFanoutExecution


class FanoutCoordinatorTest(TestCase):
    def setUp(self):
        self.repo, self.tag, self.revision = ("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333")
        event_id = "44444444-4444-4444-4444-444444444444"
        self.claim = EventClaim(event_id, "search", "worker", 1, dict(event_id=event_id, schema_version=1, sequence="9", stream="repo." + self.repo,
            repo_id=self.repo, revision=self.revision, reason="tag_id:" + self.tag, source="hub", action="tags.definition.updated", result="succeeded",
            actor_user_id="employee", actor_kind="user", request_id="request", occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")))
        self.execution = Mock(spec=SearchFanoutExecution)
        self.execution.store = Mock()
        self.source = Mock()
        self.coordinator = TagFanoutCoordinator(self.execution, source_scope=self.source, snapshot_reader=Mock())

    def test_pending_page_is_resumed_without_reenumeration(self):
        self.execution.store.load.return_value = dict(repo_id=self.repo, tag_id=self.tag, tag_revision=self.revision, state="pending")
        self.assertFalse(self.coordinator.advance(self.claim, generation="index"))
        self.source.assert_not_called()
        self.execution.advance_pending.assert_called_once_with(self.claim, generation="index")

    def test_scanned_event_uses_atomic_confirmation(self):
        self.execution.store.load.return_value = dict(repo_id=self.repo, tag_id=self.tag, tag_revision=self.revision, state="scanned")
        self.assertTrue(self.coordinator.advance(self.claim, generation="index"))
        self.execution.store.complete_fanout.assert_called_once_with(self.claim, generation="index")
        self.execution.advance_pending.assert_not_called()
