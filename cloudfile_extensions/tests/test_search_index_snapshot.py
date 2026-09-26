from contextlib import contextmanager
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.store import ResourceStore, ResourceEvidence
from cloudfile_extensions.search.snapshot import IndexSnapshotReader


class IndexSnapshotTest(TestCase):
    def setUp(self):
        self.store = object.__new__(ResourceStore)
        self.store.connection = object()
        self.store.secret = b"s" * 32
        self.cursor = Mock(connection=self.store.connection)
        self.ref = dict(repo_id="11111111-1111-1111-1111-111111111111", path="/drawing", kind="file")
        self.store._row = Mock(return_value=None)
        self.active = False

    @contextmanager
    def scope(self, cursor, ref):
        self.assertIs(cursor, self.cursor)
        self.assertEqual(ref, self.ref)
        self.active = True
        try:
            yield ResourceEvidence("native-lifecycle")
        finally:
            self.active = False

    def test_sparse_missing_resource_is_not_allocated_or_granted_access(self):
        result = IndexSnapshotReader(self.store, lifecycle_scope=self.scope)(self.cursor, self.ref)
        self.assertIsNone(result["uid"])
        self.assertEqual(result["description"], "")
        self.assertEqual(result["tags"], [])
        self.assertNotIn("access", result)
        self.assertFalse(self.active)

    def test_existing_row_tags_are_read_inside_native_scope(self):
        uid = "22222222-2222-2222-2222-222222222222"
        self.store._row.return_value = dict(uid=uid, revision=1, description="说明", local_open_type=None)
        def tags(cursor, **kwargs):
            self.assertTrue(self.active)
            self.assertEqual(kwargs, dict(resource_uid=uid, repo_id=self.ref["repo_id"]))
            return []
        with patch("cloudfile_extensions.search.snapshot.bound_tags", side_effect=tags):
            self.assertEqual(IndexSnapshotReader(self.store, lifecycle_scope=self.scope)(self.cursor, self.ref)["description"], "说明")

    def test_other_connection_and_missing_transaction_are_rejected(self):
        reader = IndexSnapshotReader(self.store, lifecycle_scope=self.scope)
        with self.assertRaises(ValueError):
            reader(Mock(connection=object()), self.ref)
        self.cursor.execute.side_effect = RuntimeError("not in transaction")
        with self.assertRaises(ContractError):
            reader(self.cursor, self.ref)
        self.store._row.assert_not_called()
