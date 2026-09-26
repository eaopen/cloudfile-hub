from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.search.execution import step_hash
from cloudfile_extensions.search.fanout_receipts import fanout_pages_complete


class FanoutReceiptProofTest(TestCase):
    def check(self, rows, batches=2):
        sql = Mock()
        sql.fetchall.return_value = rows
        return fanout_pages_complete(sql, event_id="event", generation="g1", index="resources", batches=batches)

    def test_empty_and_successful_remote_pages_are_both_required(self):
        rows = [(0, "resources", step_hash("resources", "replace", b"[]"), 1, None, None, None, None),
                (1, "resources", "a" * 64, 0, 7, "succeeded", "a" * 64, 7)]
        self.assertTrue(self.check(rows))
        self.assertFalse(self.check(rows[:1]))
        self.assertFalse(self.check(list(reversed(rows))))
        self.assertFalse(self.check(rows + [rows[0]]))

    def test_wrong_index_changed_hash_or_processing_task_rejected(self):
        for row in ((0, "other", "a" * 64, 0, 7, "succeeded", "a" * 64, 7),
                    (0, "resources", "a" * 64, 0, 7, "succeeded", "b" * 64, 7),
                    (0, "resources", "a" * 64, 0, 7, "submitted", "a" * 64, 7),
                    (0, "resources", "a" * 64, 1, None, None, None, None)):
            self.assertFalse(self.check([row], batches=1))
