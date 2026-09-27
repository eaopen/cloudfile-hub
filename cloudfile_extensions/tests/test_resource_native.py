"""Real SQL Branch fencing; RPC is an explicit immutable-history fixture."""
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.native import NativeResourceReader
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class NativeResourceReaderTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.ref = dict(repo_id=str(uuid4()), path='/part.prt', kind='file')
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE Branch(repo_id CHAR(36),name VARCHAR(20),commit_id CHAR(40),PRIMARY KEY(repo_id,name)) ENGINE=InnoDB")
            cursor.execute("INSERT INTO Branch VALUES(%s,'master',%s)", (self.ref['repo_id'], '3' * 40))
        self.api = Mock()
        self.api.get_repo.return_value = SimpleNamespace(version=1)
        self.parents = {'3' * 40: '2' * 40, '2' * 40: '1' * 40, '1' * 40: None}
        self.api.get_commit.side_effect = lambda repo, version, commit: SimpleNamespace(
            id=commit, parent_id=self.parents[commit], second_parent_id=None)
        self.objects = {'3' * 40: 'b' * 40, '2' * 40: 'a' * 40, '1' * 40: None}
        self.api.get_file_id_by_commit_and_path.side_effect = lambda repo, commit, path: self.objects[commit]
        self.api.get_dir_id_by_commit_and_path.side_effect = lambda repo, commit, path: self.objects[commit]
        self.reader = NativeResourceReader(self.api)

    def read(self, **kwargs):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                return self.reader(cursor, dict(self.ref, **kwargs))
        finally:
            self.connection.rollback()

    def test_overwrite_preserves_birth_but_recreation_changes_it(self):
        original = self.read()
        self.assertEqual(original.lifecycle_ref, 'ce14:path-birth:' + '2' * 40)
        self.objects['3' * 40] = 'c' * 40
        self.assertEqual(self.read(), original)
        self.objects['2' * 40] = None
        self.assertNotEqual(self.read(), original)

    def test_directory_uses_native_directory_lookup(self):
        self.assertEqual(self.read(kind='dir').lifecycle_ref, 'ce14:path-birth:' + '2' * 40)
        self.api.get_file_id_by_commit_and_path.assert_not_called()

    def test_missing_target_and_incomplete_history_remain_closed(self):
        self.objects['3' * 40] = None
        with self.assertRaises(ContractError) as raised:
            self.read()
        self.assertEqual(raised.exception.status, 404)
        self.objects['3' * 40] = 'b' * 40
        self.reader = NativeResourceReader(self.api, max_commits=1)
        with self.assertRaises(ContractError) as raised:
            self.read()
        self.assertEqual(raised.exception.code, 'PATH_STATE_PENDING')
