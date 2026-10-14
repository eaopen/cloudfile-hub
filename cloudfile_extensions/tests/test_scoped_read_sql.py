"""Scoped metadata authority with real SQL and C, fixture identity/lifecycle."""
import os
import unittest

from cloudfile_extensions.authorization.scoped_read import ScopedContentReadAuthority
from cloudfile_extensions.authorization.management import DirectoryManagement
from cloudfile_extensions.authorization.share_service import DirectoryShareService
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.tests import test_resource_batch_sql as fixtures


@unittest.skipUnless(os.environ.get('CF_TEST_ACL_LIBRARY'), 'requires compiled C core')
class ScopedReadSQLTest(fixtures.ResourceBatchSQLTest):

    def setUp(self):
        super().setUp()
        with self.connection.cursor() as cursor:
            for sql in (
                'CREATE TABLE SharedRepo(repo_id CHAR(36),to_email VARCHAR(255),permission VARCHAR(16)) ENGINE=InnoDB',
                'CREATE TABLE GroupUser(group_id INT,user_name VARCHAR(255)) ENGINE=InnoDB',
                'CREATE TABLE `Group`(group_id INT,parent_group_id INT) ENGINE=InnoDB',
                'CREATE TABLE GroupStructure(group_id INT,path VARCHAR(1024)) ENGINE=InnoDB',
                'CREATE TABLE InnerPubRepo(repo_id CHAR(36),permission VARCHAR(16)) ENGINE=InnoDB'):
                cursor.execute(sql)
        self.authority = ScopedContentReadAuthority(self.preparation, self.core, cloud_mode=False,
            request_id='scoped-test', lifecycle_reader=self.lifecycle)

    def shared(self):
        refs = self.references(2)
        root = dict(repo_id=refs[0]['repo_id'], path='/folder', kind='dir')
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE RepoOwner SET owner_id='another-user'")
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                share, _ = self.authority.shares.create(cursor, root, dict(path='/folder', subject=dict(
                    type='user', provider='directory', namespace='user', external_id='employee')), actor='admin')
            self.connection.commit()
        finally:
            self.connection.rollback()
        return refs, root, share

    def test_batch_scope_and_revoke_with_acl_retained(self):
        refs, root, share = self.shared()
        denied = {**root, 'path': '/sibling'}
        self.assertEqual(self.authority.consume_many([refs[0], denied, refs[1]]), ['r', None, 'r'])
        self.rule(root, 'rw', True)
        self.assertEqual(self.authority.consume_many(refs), ['rw', 'rw'])
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                self.authority.shares.delete(cursor, root, share['id'], if_match=share['etag'])
            self.connection.commit()
        finally:
            self.connection.rollback()
        self.assertEqual(self.authority.consume_many(refs), ['rw', 'rw'])
        self.assertEqual(self.authority.consume(refs[0], lambda cursor, ref: self.authority.effective_access),
            dict(read=True, write=True))

    def test_inactive_account_cannot_use_existing_share(self):
        refs, root, share = self.shared()
        with self.connection.cursor() as cursor:
            cursor.execute('UPDATE EmailUser SET is_active=0')
        self.assertEqual(self.authority.consume_many(refs), [None, None])
        with self.assertRaises(ContractError):
            self.authority.consume(refs[0], lambda cursor, ref: 'must-not-escape')

    def test_stale_directory_and_browse_root_are_not_access_grants(self):
        refs, root, share = self.shared()
        self.authority.browse_root = '/other'
        self.assertEqual(self.authority.consume_many(refs), [None, None])
        self.authority.browse_root = None
        from cloudfile_extensions.resources.store import ResourceEvidence
        self.lifecycle.return_value = ResourceEvidence('new-directory')
        self.assertEqual(self.authority.consume_many(refs), [None, None])

    def test_management_commands_do_not_mutate_acl(self):
        ref = {**self.references(1)[0], 'path': '/folder', 'kind': 'dir'}
        management = DirectoryManagement(self.preparation, self.core, request_id='share-commands', cloud_mode=False)
        service = DirectoryShareService(management, lifecycle_reader=self.lifecycle)
        value = dict(path=ref['path'], subject=dict(type='user', provider='directory', namespace='user', external_id='other'))
        request = dict(reference=ref, value=value)
        item = service.create(request)
        self.assertEqual(service.create(request), item)
        service.delete(item['id'], dict(reference=ref), if_match=item['etag'])
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_dir_acl')
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute('SELECT COUNT(*) FROM cf_dir_share')
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_share_recipient_cannot_manage_shares(self):
        refs, root, share = self.shared()
        management = DirectoryManagement(self.preparation, self.core, request_id='share-denied', cloud_mode=False)
        service = DirectoryShareService(management, lifecycle_reader=self.lifecycle)
        with self.assertRaises(ContractError) as caught:
            service.delete(share['id'], dict(reference=root), if_match=share['etag'])
        self.assertEqual(caught.exception.code, 'ACCESS_DENIED')
