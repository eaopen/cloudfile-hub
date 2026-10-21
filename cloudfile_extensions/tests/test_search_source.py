from contextlib import nullcontext
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.source import OwnedIndexSource


class OwnedIndexSourceTest(TestCase):
    def setUp(self):
        self.repo = "11111111-1111-1111-1111-111111111111"
        self.connection, self.worker = Mock(), Mock()
        self.connection.get_autocommit.return_value = True
        self.cursor = Mock(connection=self.connection)
        self.connection.cursor.return_value.__enter__ = Mock(return_value=self.cursor)
        self.connection.cursor.return_value.__exit__ = Mock(return_value=False)
        self.source = OwnedIndexSource(connection_factory=lambda: self.connection, worker_connection=self.worker,
            repo_scope=lambda connection, repo: nullcontext(), lifecycle_scope=lambda cursor, ref: nullcontext(), secret=b"s" * 32)

    def test_source_failure_rolls_back_closes_and_invalidates_cursor(self):
        with patch("cloudfile_extensions.search.source.SchemaRunner"):
            with self.assertRaises(RuntimeError):
                with self.source.scope(self.repo, self.repo, self.repo):
                    raise RuntimeError("read failure")
        self.connection.rollback.assert_called_once()
        self.connection.close.assert_called_once()
        with self.assertRaises(ContractError):
            self.source.read(self.cursor, dict(repo_id=self.repo, path="/x", kind="file"))

    def test_worker_connection_is_never_closed_or_reused(self):
        self.source.connection_factory = lambda: self.worker
        with self.assertRaises(ContractError):
            with self.source.scope(self.repo, self.repo, self.repo):
                pass
        self.worker.close.assert_not_called()

    def test_schema_failure_closes_without_opening_native_scope(self):
        with patch("cloudfile_extensions.search.source.SchemaRunner") as runner:
            runner.return_value.require_current.side_effect = RuntimeError("schema mismatch")
            with self.assertRaises(RuntimeError):
                with self.source.scope(self.repo, self.repo, self.repo):
                    pass
        self.connection.begin.assert_not_called()
        self.connection.close.assert_called_once()

    def test_attribute_source_preserves_literal_path_and_passes_actual_kind(self):
        self.cursor.fetchall.return_value = (("dir", "/a%2Fb"),)
        with patch("cloudfile_extensions.search.source.SchemaRunner"), patch("cloudfile_extensions.search.source.ResourceStore._storage"), patch("cloudfile_extensions.search.source.IndexSnapshotReader") as reader:
            reader.return_value.return_value = dict(description="说明")
            self.assertEqual(self.source.read_attribute(self.repo, "/a%2Fb"), dict(description="说明"))
            reader.return_value.assert_called_once_with(self.cursor, dict(repo_id=self.repo, path="/a%2Fb", kind="dir"))
        self.connection.rollback.assert_called_once()
        self.connection.close.assert_called_once()

    def test_ambiguous_sparse_location_never_calls_native_reader(self):
        self.cursor.fetchall.return_value = (("dir", "/x"), ("file", "/x"))
        with patch("cloudfile_extensions.search.source.SchemaRunner"), patch("cloudfile_extensions.search.source.ResourceStore._storage"), patch("cloudfile_extensions.search.source.IndexSnapshotReader") as reader:
            with self.assertRaises(ContractError):
                self.source.read_attribute(self.repo, "/x")
            reader.return_value.assert_not_called()
        self.connection.close.assert_called_once()
