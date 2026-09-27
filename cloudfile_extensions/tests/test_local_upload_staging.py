"""Real private files/FDs, not HTTP authentication or native publication proof."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest

from cloudfile_extensions.local_edit.staging import StageUnavailable, UploadStaging


@unittest.skipUnless(os.name == "posix", "POSIX server staging required")
class LocalUploadStagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cf-local-stage-")
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name).resolve())
        os.chmod(self.path, 0o700)

    def test_complete_content_is_measured_unlinked_and_readonly(self):
        data = b"actual-upload" * 9000
        with UploadStaging(self.path, maximum_bytes=len(data)) as receiver:
            with receiver.receive(io.BytesIO(data), content_length=len(data)) as result:
                self.assertEqual(result.length, len(data))
                self.assertEqual(result.sha256, hashlib.sha256(data).hexdigest())
                self.assertEqual(os.listdir(self.path), [])
                fd = result.take_fd()
                try:
                    self.assertEqual(os.fstat(fd).st_nlink, 0)
                    self.assertEqual(os.pread(fd, len(data), 0), data)
                    with self.assertRaises(OSError):
                        os.write(fd, b"changed")
                    with self.assertRaises(StageUnavailable):
                        result.take_fd()
                finally:
                    os.close(fd)

    def test_short_long_or_budget_failure_leaves_no_named_partial(self):
        with UploadStaging(self.path, maximum_bytes=4) as receiver:
            for data, length in ((b"a", 2), (b"abc", 2), (b"12345", 5), (b"", True)):
                with self.subTest(length=length):
                    with self.assertRaises(StageUnavailable):
                        receiver.receive(io.BytesIO(data), content_length=length)
                    self.assertEqual(os.listdir(self.path), [])
            with receiver.receive(io.BytesIO(b""), content_length=0) as result:
                self.assertEqual(result.length, 0)
                self.assertEqual(result.sha256, hashlib.sha256(b"").hexdigest())

    def test_unsafe_directory_or_reparse_target_rejected(self):
        os.chmod(self.path, 0o755)
        with self.assertRaises(StageUnavailable):
            UploadStaging(self.path, maximum_bytes=4)
        os.chmod(self.path, 0o700)
        link = os.path.join(self.path, "redirect")
        os.symlink(self.path, link)
        with self.assertRaises(StageUnavailable):
            UploadStaging(link, maximum_bytes=4)

    def test_closed_receiver_cannot_receive(self):
        receiver = UploadStaging(self.path, maximum_bytes=4)
        receiver.close()
        with self.assertRaises(StageUnavailable):
            receiver.receive(io.BytesIO(b"x"), content_length=1)
