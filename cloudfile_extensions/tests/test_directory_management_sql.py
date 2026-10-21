"""Directory delegation through actual transactional storage and authority."""
from cloudfile_extensions.authorization.directory_management import DelegatedDirectoryManagement
from cloudfile_extensions.authorization.share_service import DirectoryShareService
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.tests import test_scoped_read_sql as fixtures


class DirectoryManagementSQLTest(fixtures.ScopedReadSQLTest):
    def delegated(self, inherit=True):
        ref = {**self.references(1)[0], 'path': '/folder', 'kind': 'dir'}
        admins = DelegatedDirectoryManagement(self.preparation, self.core, request_id='delegate-test',
            cloud_mode=False, administrators=True)
        value = dict(path=ref['path'], kind='dir', permission='manage', inherit=inherit,
            subject=dict(type='user', provider='directory', namespace='user', external_id='employee'))
        grant = admins.mutate(ref, value=value)
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE RepoOwner SET owner_id='other'")
        return ref, admins, grant

    def test_delegation_strict_descendant_and_no_peer_revoke(self):
        ref, admins, grant = self.delegated()
        child = {**ref, 'path': '/folder/project'}
        value = dict(path=child['path'], kind='dir', permission='manage', inherit=True,
            subject={**grant['subject'], 'external_id': 'engineer'})
        child_grant = admins.mutate(child, value=value)
        self.assertEqual(child_grant['permission'], 'manage')
        for target in (ref, {**ref, 'path': '/other'}, {**ref, 'path': '/'}):
            with self.assertRaises(ContractError):
                admins.mutate(target, value={**value, 'path': target['path']})
        with self.assertRaises(ContractError):
            admins.mutate(ref, rule_id=grant['id'], if_match=grant['etag'])

    def test_exact_only_admin_cannot_expand_acl_or_share_subtree(self):
        ref, admins, grant = self.delegated(inherit=False)
        content = DelegatedDirectoryManagement(self.preparation, self.core, request_id='exact-admin', cloud_mode=False)
        value = dict(path=ref['path'], kind='dir', permission='r', inherit=False, subject=grant['subject'])
        content.mutate(ref, value=value)
        with self.assertRaises(ContractError):
            content.mutate(ref, value={**value, 'inherit': True})
        shares = DirectoryShareService(content, lifecycle_reader=self.lifecycle)
        with self.assertRaises(ContractError):
            shares.create(dict(reference=ref, value=dict(path=ref['path'], subject=grant['subject'])))

    def test_delegated_admin_can_share_without_content_access(self):
        ref, admins, grant = self.delegated()
        content = DelegatedDirectoryManagement(self.preparation, self.core, request_id='scoped-admin', cloud_mode=False)
        result = DirectoryShareService(content, lifecycle_reader=self.lifecycle).create(dict(reference=ref,
            value=dict(path=ref['path'], subject={**grant['subject'], 'external_id': 'recipient'})))
        self.assertEqual(result['subject']['external_id'], 'recipient')
        with self.assertRaises(ContractError):
            self.authority.consume(ref, lambda cursor, target: 'management is not content')
        diagnostic = self.authority.inspect_policy(ref)
        self.assertTrue(diagnostic['can_manage'])
        self.assertEqual(diagnostic['effective_permission'], 'invisible')
