from datetime import datetime, timezone
from unittest import TestCase

from cloudfile_extensions.events.read_reconciliation import summarize_read_attempts


class ReadReconciliationTest(TestCase):
    def row(self, **changes):
        value = dict(schema_version=1, source="fileserver", operation="file.download",
            request_id="request", actor_kind="user", actor_user_id="employee",
            repo_id="repo", source_path="/file", event_id="event",
            occurred_at="2026-09-27T01:00:00Z", result="attempted")
        return {**value, **changes}

    def report(self, rows, complete=True):
        return summarize_read_attempts(rows, filters=dict(repo_id="repo", start="start", end="end"),
            cutoff=100, complete=complete, now=datetime(2026, 9, 27, 2, tzinfo=timezone.utc))

    def test_unknown_is_not_an_invented_failure(self):
        report = self.report([self.row()], complete=False)
        self.assertFalse(report["scan_complete"])
        self.assertEqual(report["items"][0]["state"], "terminal_not_observed")
        self.assertNotIn("result", report["items"][0])

    def test_terminal_requires_same_subject_path_action_and_request(self):
        attempt = self.row()
        terminal = {**attempt, "result": "stream_completed"}
        self.assertEqual(self.report([terminal, attempt])["items"], [])
        for field in ("request_id", "repo_id", "actor_user_id", "operation", "source_path"):
            self.assertEqual(len(self.report([attempt, {**terminal, field: "other"}])["items"]), 1)

    def test_recent_legacy_and_other_sources_are_not_reported(self):
        rows = [{**self.row(), "occurred_at": "2026-09-27T01:59:00Z"},
            {**self.row(), "schema_version": 0}, {**self.row(), "source": "hub"}]
        self.assertEqual(self.report(rows)["items"], [])
