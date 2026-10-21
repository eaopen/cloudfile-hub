"""Directory API services with SQL/C authority and immutable RPC page fixtures."""
from types import SimpleNamespace
from unittest.mock import patch, Mock

from cloudfile_extensions.authorization.directory_entries import DirectoryEntriesService
from cloudfile_extensions.authorization.directory_management import DelegatedDirectoryManagement
from cloudfile_extensions.authorization.directory_scope import DirectoryScopeService
from cloudfile_extensions.authorization.scoped_read import ScopedContentWriteAuthority
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.tests import test_scoped_read_sql as fixtures


class DirectoryAPISQLTest(fixtures.ScopedReadSQLTest):
    def test_native_page_filters_denied_children_and_pins_pagination(self):
        refs, root, _ = self.shared()
        with self.connection.cursor() as cursor:
            cursor.execute('CREATE TABLE Branch(repo_id CHAR(36),name VARCHAR(10),commit_id CHAR(40)) ENGINE=InnoDB')
            cursor.execute("INSERT INTO Branch VALUES(%s,'master',%s)", (root['repo_id'], 'a' * 40))
        self.rule(refs[0], 'none')
        api = Mock()
        api.list_dir_by_commit_and_path.return_value = [SimpleNamespace(obj_name='item-0', mode=0o100644),
            SimpleNamespace(obj_name='item-1', mode=0o100644), SimpleNamespace(obj_name='next', mode=0o100644)]
        service = DirectoryEntriesService(self.authority)
        with patch('cloudfile_extensions.search.native_directory._native_api', return_value=api):
            result = service.list(dict(reference=root, shared_root='/folder'), limit=2)
            self.assertEqual([item['name'] for item in result['items']], ['item-1'])
            self.assertEqual(result['next_after'], 'a' * 40 + ':2')
            api.list_dir_by_commit_and_path.assert_called_once_with(root['repo_id'], 'a' * 40, '/folder', 0, 3)
            with self.assertRaises(ContractError):
                service.list(dict(reference={**root, 'path': '/sibling'}))
            with self.assertRaises(ContractError) as error:
                service.list(dict(reference=root), after='b' * 40 + ':2')
            self.assertEqual(error.exception.status, 409)

    def test_write_preflight_needs_acl_and_respects_native_readonly(self):
        refs, root, _ = self.shared()
        authority = ScopedContentWriteAuthority(self.preparation, self.core, cloud_mode=False,
            request_id='write-test', lifecycle_reader=self.lifecycle)
        with self.assertRaises(ContractError):
            authority.consume(refs[0], lambda cursor, ref: 'write')
        self.rule(root, 'rw', True)
        self.assertEqual(authority.consume(refs[0], lambda cursor, ref: 'write'), 'write')
        with self.connection.cursor() as cursor:
            cursor.execute('UPDATE RepoInfo SET status=1')
        with self.assertRaises(ContractError):
            authority.consume(refs[0], lambda cursor, ref: 'write')

    def test_scope_revoke_is_atomic_conditional_and_never_deletes_acl(self):
        root = {**self.references(1)[0], 'path': '/folder', 'kind': 'dir'}
        authority = DelegatedDirectoryManagement(self.preparation, self.core, request_id='scope-test', cloud_mode=False)
        service = DirectoryScopeService(authority, lifecycle_reader=self.lifecycle)
        def create(path):
            return service.create(dict(reference={**root, 'path': path}, value=dict(path=path,
                subject=dict(type='user', provider='directory', namespace='user', external_id='recipient'))))
        a, b, sibling = create('/folder'), create('/folder/child'), create('/folder2')
        self.rule(root, 'rw', True)
        query = dict(reference=root, domain='shares')
        self.assertEqual({item['id'] for item in service.list_scope(query)['items']}, {a['id'], b['id']})
        items = [dict(id=item['id'], etag=item['etag']) for item in (a, b)]
        with self.assertRaises(ContractError):
            service.revoke(dict(query, items=[items[0], {**items[1], 'etag': '"stale"'}]), idempotency_key='failed-batch')
        self.assertEqual(len(service.list_scope(query)['items']), 2)
        request = dict(query, items=items)
        result = service.revoke(request, idempotency_key='revoke-batch')
        self.assertEqual(service.revoke(request, idempotency_key='revoke-batch'), result)
        self.assertEqual(service.list_scope(query)['items'], [])
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_dir_acl')
            self.assertEqual(cursor.fetchone()[0], 4)
            cursor.execute('SELECT id FROM cf_dir_acl WHERE share_mode=1')
            self.assertEqual(cursor.fetchall(), ((sibling['id'],),))

    def test_batch_revoke_cannot_remove_delegated_admin_root_or_sibling(self):
        root = {**self.references(1)[0], 'path': '/folder', 'kind': 'dir'}
        manager = DelegatedDirectoryManagement(self.preparation, self.core,
            request_id='grant-scope-test', cloud_mode=False, administrators=True)
        value = dict(path=root['path'], kind='dir', permission='manage', inherit=True,
            subject=dict(type='user', provider='directory', namespace='user', external_id='employee'))
        own = manager.mutate(root, value=value)
        child_ref = {**root, 'path': '/folder/child'}
        child = manager.mutate(child_ref, value={**value, 'path': child_ref['path'],
            'subject': {**value['subject'], 'external_id': 'recipient'}})
        sibling_ref = {**root, 'path': '/folder2'}
        sibling = manager.mutate(sibling_ref, value={**value, 'path': sibling_ref['path']})
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE RepoOwner SET owner_id='another-user'")
        authority = DelegatedDirectoryManagement(self.preparation, self.core,
            request_id='revoke-scope-test', cloud_mode=False)
        service = DirectoryScopeService(authority, lifecycle_reader=self.lifecycle)
        query = dict(reference=root, domain='admins')
        for forbidden in (own, sibling):
            request = dict(query, items=[dict(id=item['id'], etag=item['etag']) for item in (child, forbidden)])
            with self.assertRaises(ContractError) as error:
                service.revoke(request, idempotency_key='invalid-' + forbidden['id'])
            self.assertEqual(error.exception.status, 403)
            self.assertEqual({item['id'] for item in service.list_scope(query)['items']}, {own['id'], child['id']})
        result = service.revoke(dict(query, items=[dict(id=child['id'], etag=child['etag'])]),
            idempotency_key='remove-child')
        self.assertEqual(result['items'], [dict(id=child['id'], path=child_ref['path'], deleted=True)])

    def test_explicit_factory_keeps_legacy_management_and_library_access(self):
        from contextlib import contextmanager
        from cloudfile_extensions.authorization.runtime import PolicyServiceFactory, AuthenticatedPolicyActor
        from cloudfile_extensions.authorization.service import DirectoryPolicyService
        from cloudfile_extensions.authorization.directory_service import DirectoryService
        from cloudfile_extensions.authorization.read import ContentReadAuthority
        refs, root, _ = self.shared()
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE RepoOwner SET owner_id='native-user'")
        grantor = DelegatedDirectoryManagement(self.preparation, self.core,
            request_id='grant-entry-test', cloud_mode=False, administrators=True)
        grantor.mutate(root, value=dict(path=root['path'], kind='dir', permission='manage', inherit=True,
            subject=dict(type='user', provider='directory', namespace='user', external_id='employee')))
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE RepoOwner SET owner_id='another-user'")
        @contextmanager
        def preparation_scope(actor, request_id):
            yield self.preparation
        factory = PolicyServiceFactory(authenticate=lambda request: AuthenticatedPolicyActor('employee', 'native-user'),
            preparation_scope=preparation_scope, core=self.core, cloud_mode=False, lifecycle_reader=self.lifecycle)
        with factory(None, 'normal-entry') as normal:
            self.assertIs(type(normal), DirectoryPolicyService)
            with self.assertRaises(ContractError):
                normal.list('acl', dict(reference=root))
        with factory.directory(None, 'directory-entry') as directory:
            self.assertIs(type(directory), DirectoryService)
            self.assertEqual(len(directory.list('shares', dict(reference=root))['items']), 1)
            self.assertEqual(directory.resolve_directory(dict(reference=root))['permission'], 'r')
        normal_read = ContentReadAuthority(self.preparation, self.core, request_id='normal-user', cloud_mode=False)
        with self.assertRaises(ContractError):
            normal_read.consume(refs[0], lambda cursor, ref: 'normal entry')
