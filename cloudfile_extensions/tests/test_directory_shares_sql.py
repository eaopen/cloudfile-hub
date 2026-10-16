"""Real isolated SQL tests: sharing and ACL permissions share one record and revision."""
from uuid import uuid4

from cloudfile_extensions.authorization.shares import DirectoryShares
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.store import ResourceEvidence
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class DirectorySharesSQLTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.birth = 'original-directory'
        self.store = DirectoryShares(lifecycle_reader=lambda cursor, ref: ResourceEvidence(self.birth))
        self.ref = dict(repo_id=str(uuid4()), path='/team', kind='dir')
        self.subject = dict(type='user', provider='directory', namespace='user', external_id='u1')
        self.value = dict(path='/team', subject=self.subject)

    def test_create_idempotent_and_revoke_retains_library_acl(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                first, created = self.store.create(cursor, self.ref, self.value, actor='admin')
                self.assertTrue(created)
                again, created = self.store.create(cursor, self.ref, self.value, actor='admin2')
                self.assertFalse(created)
                self.assertEqual(first, again)
                cursor.execute('SELECT COUNT(*) FROM cf_dir_acl')
                self.assertEqual(cursor.fetchall(), ((1,),))
                self.assertEqual(self.store.candidates(cursor, {**self.ref, 'path': '/team/file', 'kind': 'file'}, [self.subject]), [self.value])
                self.store.delete(cursor, self.ref, first['id'], if_match=first['etag'])
                cursor.execute('SELECT COUNT(*) FROM cf_dir_acl')
                self.assertEqual(cursor.fetchall(), ((1,),))
                self.assertEqual(self.store.candidates(cursor, self.ref, [self.subject]), [])
        finally:
            self.connection.rollback()

    def test_scope_identity_and_lifecycle(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                item, _ = self.store.create(cursor, self.ref, self.value, actor='admin')
                for path in ('/', '/team2', '/other'):
                    self.assertEqual(self.store.candidates(cursor, {**self.ref, 'path': path}, [self.subject]), [])
                self.assertEqual(self.store.candidates(cursor, self.ref, [{**self.subject, 'external_id': 'u2'}]), [])
                self.birth = 'recreated-directory'
                self.assertEqual(self.store.candidates(cursor, self.ref, [self.subject]), [])
                with self.assertRaises(ContractError):
                    self.store.create(cursor, self.ref, self.value, actor='admin')
                self.store.delete(cursor, self.ref, item['id'], if_match=item['etag'])
        finally:
            self.connection.rollback()

    def test_legacy_create_never_promotes_existing_deny(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                item, _ = self.store.create(cursor, self.ref, self.value, actor='admin')
                cursor.execute("UPDATE cf_dir_acl SET share_mode=0,lifecycle_ref='',permission='none' WHERE id=%s",
                               (item['id'],))
                with self.assertRaises(ContractError) as result:
                    self.store.create(cursor, self.ref, self.value, actor='admin')
                self.assertEqual(result.exception.status, 409)
                cursor.execute('SELECT permission,share_mode FROM cf_dir_acl WHERE id=%s', (item['id'],))
                self.assertEqual(cursor.fetchall(), (('none', 0),))
        finally:
            self.connection.rollback()

    def test_wrong_revision_cannot_delete_share(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                item, _ = self.store.create(cursor, self.ref, self.value, actor='admin')
                with self.assertRaises(ContractError):
                    self.store.delete(cursor, self.ref, item['id'], if_match='"wrong"')
                self.assertEqual(self.store.candidates(cursor, self.ref, [self.subject]), [self.value])
        finally:
            self.connection.rollback()

    def test_noninherited_shared_acl_only_qualifies_exact_directory(self):
        self.connection.begin()
        with self.connection.cursor() as cursor:
            item, _ = self.store.create(cursor, self.ref, self.value, actor='admin')
            cursor.execute("UPDATE cf_dir_acl SET inherit=0,permission='rw' WHERE id=%s", (item['id'],))
            # Compatibility creation must preserve an existing ACL's permission
            # and inheritance, even when repeated by another administrator.
            same, changed = self.store.create(cursor, self.ref, self.value, actor='admin2')
            self.assertFalse(changed)
            self.assertEqual((same['permission'], same['inherit']), ('rw', False))
            self.assertEqual(self.store.candidates(cursor, self.ref, [self.subject]), [self.value])
            self.assertEqual(self.store.candidates(cursor, {**self.ref, 'path': '/team/file', 'kind': 'file'}, [self.subject]), [])
        self.connection.rollback()
