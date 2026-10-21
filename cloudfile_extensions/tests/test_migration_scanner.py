import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.migration.scanner import SourceScanner


class SourceScannerTests(unittest.TestCase):
    def test_streams_empty_directories_zero_bytes_and_unicode_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "empty").mkdir()
            (root / "零字节").touch()
            (root / "drawing.prt").write_bytes(b"drawing")
            stream = SourceScanner(str(root), content_hash=True).scan()
            self.assertIs(iter(stream), stream)
            values = {row["path"]: row for row in stream}
            self.assertEqual(values["empty"], {"path": "empty", "kind": "directory"})
            self.assertEqual(values["零字节"]["size"], 0)
            self.assertEqual(values["drawing.prt"]["sha256"], hashlib.sha256(b"drawing").hexdigest())
            self.assertEqual((root / "drawing.prt").read_bytes(), b"drawing")

    def test_never_follows_file_or_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "directory").mkdir()
            (root / "directory" / "file").touch()
            (root / "file-link").symlink_to(root / "directory" / "file")
            (root / "directory-link").symlink_to(root / "directory", target_is_directory=True)
            values = {row["path"]: row for row in SourceScanner(str(root)).scan()}
            for path in ("file-link", "directory-link"):
                self.assertEqual(values[path]["error"], "SOURCE_SYMLINK")
            self.assertNotIn("directory-link/file", values)

    def test_special_files_are_reported_without_opening_or_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.mkfifo(root / "pipe")
            self.assertEqual(list(SourceScanner(str(root)).scan())[0]["error"], "SOURCE_SPECIAL_FILE")

    def test_cancel_and_depth_limit_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "a" / "b").mkdir(parents=True)
            with self.assertRaises(ContractError) as caught:
                list(SourceScanner(str(root), cancelled=lambda: True).scan())
            self.assertEqual(caught.exception.code, "IMPORT_CANCELLED")
            rows = list(SourceScanner(str(root), maximum_depth=1).scan())
            self.assertEqual(rows[-1]["error"], "SOURCE_DEPTH_LIMIT")

    def test_root_symlink_and_relative_root_are_rejected(self):
        with self.assertRaises(ValueError):
            SourceScanner("relative")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "link").symlink_to(root, target_is_directory=True)
            with self.assertRaises(ContractError):
                list(SourceScanner(str(root / "link")).scan())
