"""Retention eligibility source regressions; no filesystem/SQL proof."""
import unittest
from cloudfile_extensions.events.retention import removable


class AuditRetentionTests(unittest.TestCase):
    def setUp(self):
        self.uid = "11111111-1111-4111-8111-111111111111"
        self.name = self.uid + ".2.csv"
        self.reference = "audit-export:" + self.name
        self.job = dict(job_id=self.uid, kind="audit.export", actor_kind="user",
            barrier_active=False, scope=dict(type="repo", provider="cloudfile", external_id=self.uid),
            lease_epoch=2, status="running", result_ref=None, checkpoint=None)

    def eligible(self, **changes):
        return removable({**self.job, **changes}, job_id=self.uid, epoch=2, name=self.name, now=1000)

    def test_running_or_unknown_files_are_not_eligible(self):
        self.assertFalse(self.eligible())
        self.assertFalse(self.eligible(kind="other"))
        self.assertFalse(self.eligible(lease_epoch=1))
        self.assertFalse(self.eligible(barrier_active=True))

    def test_fenced_old_attempts_and_terminal_results_are_eligible(self):
        self.assertTrue(self.eligible(lease_epoch=3))
        for status in ("failed", "cancelled", "queued"):
            self.assertTrue(self.eligible(status=status))

    def test_only_valid_expired_success_is_eligible(self):
        for expiry, expected in ((999, True), (1001, False), (float("nan"), False),
                                 (True, False), ("999", False)):
            self.assertEqual(self.eligible(status="succeeded", result_ref=self.reference,
                checkpoint=dict(result_ref=self.reference, expires_at=expiry)), expected)
        self.assertFalse(self.eligible(status="succeeded", result_ref="other",
            checkpoint=dict(result_ref=self.reference, expires_at=999)))
