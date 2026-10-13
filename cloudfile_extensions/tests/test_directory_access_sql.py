"""Directory discovery and address boundaries using real SQL and policy C."""
from cloudfile_extensions.authorization.directory_access import DirectoryAccessService
from cloudfile_extensions.authorization.management import DirectoryManagement
from cloudfile_extensions.authorization.share_service import DirectoryShareService
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.tests import test_scoped_read_sql as fixtures


class DirectoryAccessSQLTest(fixtures.ScopedReadSQLTest):
    def test_composed_service_returns_provider_and_keeps_domains_separate(self):
        from cloudfile_extensions.authorization.directory_management import DelegatedDirectoryManagement
        from cloudfile_extensions.authorization.directory_service import DirectoryService
        ref = {**self.references(1)[0], 'path': '/folder', 'kind': 'dir'}
        service = DirectoryService(DelegatedDirectoryManagement(self.preparation, self.core,
            request_id='composed-directory', cloud_mode=False), lifecycle_reader=self.lifecycle)
        value = dict(path=ref['path'], subject=dict(type='user', provider='directory', namespace='user', external_id='recipient'))
        share = service.create('shares', dict(reference=ref, value=value), idempotency_key='new-share')
        self.assertEqual(service.list('shares', dict(reference=ref))['items'], [share])
        self.assertEqual(service.list('acl', dict(reference=ref)), dict(items=[], next_after=None, subject_provider='directory'))
        delegated = service.create('admins', dict(reference=ref, value={**value, 'permission': 'manage', 'kind': 'dir', 'inherit': True}),
            idempotency_key='new-admin')
        self.assertEqual(delegated['permission'], 'manage')
        self.assertEqual(service.list('acl', dict(reference=ref))['items'], [])

    def test_share_is_discoverable_and_address_root_is_server_selected(self):
        _, root, _ = self.shared()
        service = DirectoryAccessService(self.authority)
        child = {**root, 'path': '/folder/child'}
        self.assertEqual(service.resolve(dict(reference=child))['root_path'], '/folder')
        result = service.shared_with_me()
        self.assertEqual([item['reference'] for item in result['items']], [root])
        self.assertEqual(result['items'][0]['permission'], 'r')
        with self.assertRaises(ContractError):
            service.resolve(dict(reference={**root, 'path': '/' }))
        with self.assertRaises(ContractError):
            service.resolve(dict(reference=child, shared_root='/folder/child'))

    def test_independent_acl_address_not_added_to_shared_list(self):
        ref = {**self.references(1)[0], 'path': '/folder', 'kind': 'dir'}
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE RepoOwner SET owner_id='another-user'")
        self.rule(ref, 'rw', True)
        service = DirectoryAccessService(self.authority)
        result = service.resolve(dict(reference={**ref, 'path': '/folder/child'}))
        self.assertEqual((result['root_path'], result['permission']), ('/folder', 'rw'))
        self.assertEqual(service.shared_with_me()['items'], [])

    def test_denied_share_is_filtered_and_invalid_cursor_is_client_error(self):
        _, root, _ = self.shared()
        self.rule(root, 'none', True)
        service = DirectoryAccessService(self.authority)
        self.assertEqual(service.shared_with_me()['items'], [])
        with self.assertRaises(ContractError) as error:
            service.shared_with_me(after='-' * 36 + ':' + 'a' * 64)
        self.assertEqual(error.exception.status, 400)

    def test_empty_filtered_page_advances_without_leaking_denied_path(self):
        from cloudfile_extensions.authorization.rules import digest
        _, root, share = self.shared()
        other = {**root, 'path': '/another'}
        self.connection.begin()
        with self.connection.cursor() as cursor:
            self.authority.shares.create(cursor, other, dict(path=other['path'], subject=share['subject']), actor='admin')
        self.connection.commit()
        first, second = sorted((root, other), key=lambda item: digest(item['path']))
        self.rule(first, 'none', True)
        service = DirectoryAccessService(self.authority)
        page = service.shared_with_me(limit=1)
        self.assertEqual(page['items'], [])
        self.assertIsNotNone(page['next_after'])
        next_page = service.shared_with_me(limit=1, after=page['next_after'])
        self.assertEqual(next_page['items'][0]['reference'], second)
        self.assertIsNone(next_page['next_after'])

    def test_retried_creation_after_delete_does_not_restore_share(self):
        ref = {**self.references(1)[0], 'path': '/folder', 'kind': 'dir'}
        management = DirectoryManagement(self.preparation, self.core, request_id='retry-test', cloud_mode=False)
        service = DirectoryShareService(management, lifecycle_reader=self.lifecycle)
        value = dict(path=ref['path'], subject=dict(type='user', provider='directory', namespace='user', external_id='other'))
        request = dict(reference=ref, value=value)
        item = service.create(request, idempotency_key='create-share')
        self.assertEqual(service.list(dict(reference=ref))['items'][0]['id'], item['id'])
        deleted = service.delete(item['id'], dict(reference=ref), if_match=item['etag'], idempotency_key='delete-share')
        self.assertEqual(service.delete(item['id'], dict(reference=ref), if_match=item['etag'], idempotency_key='delete-share'), deleted)
        self.assertEqual(service.create(request, idempotency_key='create-share'), item)
        self.assertEqual(service.list(dict(reference=ref))['items'], [])
        with self.assertRaises(ContractError) as error:
            service.create(dict(reference=ref, value={**value, 'subject': {**value['subject'], 'external_id': 'third'}}),
                idempotency_key='create-share')
        self.assertEqual(error.exception.status, 409)
