"""Public progress shape only; not management authorization evidence."""
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.migration.public_status import public_status


class MigrationPublicStatusTests(unittest.TestCase):
    def job(self, **changes):
        return dict(dict(job_id="fixture-job", kind="migration.stage", status="succeeded", step="finished",
            lease_epoch=2 ** 64 - 1, attempts=1, error_code=None,
            checkpoint=dict(files=2 ** 53 + 1, bytes=7, private_path="private", token="credential", import_verified=False)), **changes)

    def test_integer_precision_and_private_checkpoint_fields(self):
        value = public_status(self.job())
        self.assertEqual(value["lease_epoch"], str(2 ** 64 - 1))
        self.assertEqual(value["progress"]["files"], str(2 ** 53 + 1))
        self.assertNotIn("private", repr(value))
        self.assertNotIn("credential", repr(value))
        self.assertFalse(value["import_verified"])

    def test_copy_verified_only_for_successful_verification_job(self):
        for status in ("running", "failed", "cancelled", "succeeded"):
            value = public_status(self.job(kind="migration.verify-copy", status=status,
                checkpoint=dict(copy_verified=True, import_verified=False)))
            self.assertEqual(value["copy_verified"], status == "succeeded")

    def test_corrupt_progress_and_import_success_are_rejected(self):
        for checkpoint in (dict(files=True), dict(bytes=-1), dict(import_verified=True)):
            with self.assertRaises(ContractError):
                public_status(self.job(checkpoint=checkpoint))
