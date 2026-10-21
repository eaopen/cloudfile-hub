from contextlib import contextmanager
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
import stat

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.native_directory import NativeCommitDirectoryReader


class NativeCommitDirectoryTest(TestCase):
    def setUp(self):
        self.held = False
        @contextmanager
        def scope(repo, commit):
            self.held = True
            try:
                yield
            finally:
                self.held = False
        self.reader = NativeCommitDirectoryReader(snapshot_scope=scope)
        self.options = dict(repo_id="11111111-1111-4111-8111-111111111111", commit_id="a" * 40, path="/", limit=1)

    def test_real_api_is_commit_specific_bounded_and_guarded(self):
        api = Mock()
        def listing(*args):
            self.assertTrue(self.held)
            return [SimpleNamespace(obj_name="literal%2F.prt", mode=stat.S_IFREG), SimpleNamespace(obj_name="folder", mode=stat.S_IFDIR)]
        api.list_dir_by_commit_and_path.side_effect = listing
        with patch("cloudfile_extensions.search.native_directory._native_api", return_value=api):
            page = self.reader.page(**self.options)
        api.list_dir_by_commit_and_path.assert_called_once_with(self.options["repo_id"], "a" * 40, "/", 0, 2)
        self.assertEqual(page["items"][0]["path"], "/literal%2F.prt")
        self.assertEqual(page["next_offset"], 1)
        self.assertFalse(self.held)

    def test_invalid_entries_and_unbounded_response_rejected(self):
        for entries in ([SimpleNamespace(obj_name="../x", mode=stat.S_IFREG)], [SimpleNamespace(obj_name="x", mode=stat.S_IFLNK)], [SimpleNamespace(obj_name="x", mode=stat.S_IFREG)] * 3, None):
            api = Mock()
            api.list_dir_by_commit_and_path.return_value = entries
            with patch("cloudfile_extensions.search.native_directory._native_api", return_value=api):
                with self.assertRaises(ContractError):
                    self.reader.page(**self.options)
            self.assertFalse(self.held)

    def test_missing_guard_and_invalid_position_fail_before_rpc(self):
        with self.assertRaises(ValueError):
            NativeCommitDirectoryReader(snapshot_scope=None)
        with patch("cloudfile_extensions.search.native_directory._native_api") as api:
            with self.assertRaises(ValueError):
                self.reader.page(**self.options, offset=-1)
            api.assert_not_called()
