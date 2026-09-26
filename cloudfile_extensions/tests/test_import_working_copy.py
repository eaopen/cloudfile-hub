"""Actual isolated filesystem copy cases; no native sync/target proof."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.migration.working_copy import WorkingCopyBuilder


class ImportWorkingCopyTests(unittest.TestCase):
    def test_copy_preserves_source_and_keeps_manifest_outside_data(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as work:
            original = Path(source)
            (original / "empty").mkdir()
            (original / "UG图纸.prt").write_bytes(b"drawing")
            attempt = str(uuid4())
            result = WorkingCopyBuilder(sources={"registered": source}, work_root=work).build(
                "registered", attempt_id=attempt, checkpoint=lambda _: False)
            self.assertEqual(Path(result.folder, "UG图纸.prt").read_bytes(), b"drawing")
            self.assertEqual((original / "UG图纸.prt").read_bytes(), b"drawing")
            self.assertTrue(Path(result.folder, "empty").is_dir())
            self.assertFalse(Path(result.folder, "manifest.ndjson").exists())
            manifest = Path(work, attempt, "manifest.ndjson").read_bytes()
            self.assertEqual(result.manifest_sha256, hashlib.sha256(manifest).hexdigest())
            self.assertEqual((result.files, result.directories, result.bytes), (1, 1, 7))
            self.assertIs(result.source_snapshot_verified, False)
            self.assertNotIn(work, repr(result))

    def test_links_and_cancellation_preserve_attempt_evidence(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as work:
            (Path(source) / "link").symlink_to(source, target_is_directory=True)
            builder = WorkingCopyBuilder(sources={"registered": source}, work_root=work)
            for cancel in (False, True):
                attempt = str(uuid4())
                with self.assertRaises(ContractError):
                    builder.build("registered", attempt_id=attempt, checkpoint=lambda _: cancel)
                self.assertTrue(Path(work, attempt, "manifest.ndjson").exists())
                self.assertTrue(Path(source, "link").is_symlink())

    def test_overlapping_volumes_are_rejected(self):
        with tempfile.TemporaryDirectory() as source:
            with self.assertRaises(ValueError):
                WorkingCopyBuilder(sources={"registered": source}, work_root=source)
