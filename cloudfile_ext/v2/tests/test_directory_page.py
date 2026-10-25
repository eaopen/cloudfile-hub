"""Paged CE directory listing through the V2 authority; native RPC is a test double."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from rest_framework.test import APIRequestFactory, force_authenticate

from cloudfile_ext.v2.acl_policy import Principal, PolicyError, Rule
from cloudfile_ext.v2.acl_runtime import ACLUnavailable, Authority, DirectoryChanged

RID = '00000000-0000-4000-8000-000000000001'
P = Principal('external', 'uid')
DIR = 'a' * 40
OTHER = 'b' * 40


def dirent(name, kind='file'):
    return SimpleNamespace(obj_id='c' * 40, obj_name=name, mode=0o040755 if kind == 'dir' else 0o100644,
                           mtime=1760000000, size=7)


class PageTests(TestCase):
    def setUp(self):
        ttl = patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=0)
        ttl.start()
        self.addCleanup(ttl.stop)

    def authority(self, base='rw', rules=(), version=1):
        store = Mock()
        store.library.return_value = tuple(rules)
        api = Mock()
        api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=version)
        api.get_repo_status.return_value = 0
        api.check_permission.return_value = base
        api.get_dir_id_by_path.return_value = DIR
        return Authority('native@auth.local', principal=P, rules=store, api=api)

    def test_window_probes_one_extra_native_entry_and_cursor_is_raw(self):
        auth = self.authority()
        auth.api.list_dir_by_dir_id.return_value = [dirent('a'), dirent('b'), dirent('c')]
        page = auth.page(RID, '/docs', start=50, limit=2)
        auth.api.list_dir_by_dir_id.assert_called_once_with(RID, DIR, 50, 3)
        self.assertEqual([entry.obj_name for entry, *_ in page['items']], ['a', 'b'])
        self.assertEqual((page['scanned_count'], page['next_start'], page['dir_id']), (2, 52, DIR))

    def test_tail_window_is_exhausted(self):
        auth = self.authority()
        auth.api.list_dir_by_dir_id.return_value = [dirent('a')]
        page = auth.page(RID, '/docs', start=4, limit=2)
        self.assertEqual((page['scanned_count'], page['next_start']), (1, None))

    def test_all_hidden_window_is_empty_but_not_exhausted(self):
        auth = self.authority(rules=(Rule(RID, '/docs/x', 'external', 'user', 'user', 'uid', 'invisible'),
                                     Rule(RID, '/docs/y', 'external', 'user', 'user', 'uid', 'invisible')))
        auth.api.list_dir_by_dir_id.return_value = [dirent('x', 'dir'), dirent('y', 'dir'), dirent('z', 'dir')]
        page = auth.page(RID, '/docs', start=0, limit=2)
        self.assertEqual(page['items'], [])
        self.assertEqual((page['scanned_count'], page['next_start']), (2, 2))

    def test_hidden_child_metadata_is_not_returned(self):
        auth = self.authority(rules=(Rule(RID, '/docs/secret', 'external', 'user', 'user', 'uid', 'invisible'),))
        auth.api.list_dir_by_dir_id.return_value = [dirent('open', 'dir'), dirent('secret', 'dir'), dirent('f.txt')]
        page = auth.page(RID, '/docs', start=0, limit=10)
        self.assertEqual([(e.obj_name, kind, perm) for e, _, kind, perm in page['items']],
                         [('open', 'dir', 'rw'), ('f.txt', 'file', 'rw')])

    def test_requested_revision_must_match_before_reading(self):
        auth = self.authority()
        with self.assertRaises(DirectoryChanged):
            auth.page(RID, '/docs', start=200, limit=200, if_dir_id=OTHER)
        auth.api.list_dir_by_dir_id.assert_not_called()

    def test_directory_changed_during_listing_is_a_conflict(self):
        auth = self.authority()
        auth.api.get_dir_id_by_path.side_effect = [DIR, OTHER]
        auth.api.list_dir_by_dir_id.return_value = [dirent('a')]
        with self.assertRaises(DirectoryChanged):
            auth.page(RID, '/docs', start=0, limit=50, if_dir_id=DIR)
        # DirectoryEntries keeps its existing 503 contract for this case.
        self.assertTrue(issubclass(DirectoryChanged, ACLUnavailable))

    def test_v0_library_pages_the_whole_object(self):
        auth = self.authority(version=0)
        auth.api.list_dir_by_dir_id.return_value = [dirent(str(i)) for i in range(5)]
        page = auth.page(RID, '/docs', start=2, limit=2)
        auth.api.list_dir_by_dir_id.assert_called_once_with(RID, DIR, -1, -1)
        self.assertEqual([e.obj_name for e, *_ in page['items']], ['2', '3'])
        self.assertEqual(page['next_start'], 4)
        self.assertIsNone(auth.page(RID, '/docs', start=4, limit=2)['next_start'])

    def test_unknown_library_version_fails_closed(self):
        auth = self.authority(version=None)
        with self.assertRaises(ACLUnavailable):
            auth.page(RID, '/docs', start=0, limit=50)
        auth.api.list_dir_by_dir_id.assert_not_called()

    def test_native_window_larger_than_requested_fails_closed(self):
        auth = self.authority()
        auth.api.list_dir_by_dir_id.return_value = [dirent(str(i)) for i in range(4)]
        with self.assertRaises(ACLUnavailable):
            auth.page(RID, '/docs', start=0, limit=2)

    def test_directory_only_grant_pages_without_library_permission(self):
        share = Rule(RID, '/projects/shared', 'external', 'user', 'user', 'uid', 'r', True, True)
        auth = self.authority(base=None, rules=(share,))
        auth.store.shared.return_value = [(share, 'v')]
        auth.api.list_dir_by_dir_id.return_value = [dirent('a.txt')]
        page = auth.page(RID, '/projects/shared', start=0, limit=50)
        self.assertEqual(page['parent'].permission, 'r')
        self.assertEqual([perm for *_, perm in page['items']], ['r'])
        for path in ('/', '/projects'):
            with self.assertRaises(PermissionError):
                auth.page(RID, path, start=0, limit=50)

    def test_revoked_permission_is_decided_again_on_the_next_request(self):
        auth = self.authority(rules=(Rule(RID, '/docs', 'external', 'user', 'user', 'uid', 'invisible'),))
        with self.assertRaises(PermissionError):
            auth.page(RID, '/docs', start=200, limit=200, if_dir_id=DIR)
        auth.api.list_dir_by_dir_id.assert_not_called()

    def test_rule_store_failure_is_not_a_grant(self):
        auth = self.authority()
        auth.store.library.side_effect = RuntimeError('sql down')
        with self.assertRaises(RuntimeError):
            auth.page(RID, '/docs', start=0, limit=50)
        auth.api.list_dir_by_dir_id.assert_not_called()

    def test_bounded_native_window_for_50_500_5000_entries(self):
        """One native window and one library-rule read, regardless of directory size.

        The mocked CE RPC slices the raw dataset; this verifies orchestration
        only, not production I/O or real directory sorting latency.
        """
        for count in (50, 500, 5000):
            with self.subTest(raw_entries=count):
                auth = self.authority()
                objects = [dirent('file-%05d.txt' % n) for n in range(count)]
                auth.api.list_dir_by_dir_id.side_effect = (
                    lambda repo, dir_id, offset, limit: objects[offset:offset + limit])
                page = auth.page(RID, '/docs', start=0, limit=50)
                self.assertEqual(len(page['items']), 50)
                self.assertEqual(page['scanned_count'], 50)
                self.assertEqual(page['next_start'], None if count == 50 else 50)
                auth.api.list_dir_by_dir_id.assert_called_once_with(RID, DIR, 0, 51)
                auth.store.library.assert_called_once_with(RID)
                auth.api.check_permission.assert_called_once_with(RID, 'native@auth.local')

    def test_page_bounds(self):
        auth = self.authority()
        for start, limit in ((-1, 50), (0, 0), (0, 501), (2147483647, 1), ('0', 50)):
            with self.assertRaises(PolicyError):
                auth.page(RID, '/docs', start=start, limit=limit)

    def test_entries_contract_is_unchanged(self):
        auth = self.authority()
        auth.api.list_dir_by_dir_id.return_value = [dirent('a'), dirent('b')]
        result = auth.entries(RID, '/docs', limit=1)
        auth.api.list_dir_by_dir_id.assert_called_once_with(RID, DIR, 0, 2)
        self.assertEqual(result, dict(data=[dict(repo_id=RID, path='/docs/a', name='a', kind='file', permission='rw')],
                                      root_path='/', next_offset=1))
        with self.assertRaises(PolicyError):
            auth.entries(RID, '/docs', limit=101)


class DirViewPageTests(TestCase):
    def request(self, params):
        from seahub.api2.endpoints.dir import DirView
        request = APIRequestFactory().get('/api/v2.1/repos/%s/dir/' % RID, params)
        force_authenticate(request, SimpleNamespace(username='native@auth.local', is_authenticated=True,
                                                    is_staff=False, is_active=True))
        return DirView.as_view()(request, repo_id=RID)

    def page(self, **kwargs):
        from cloudfile_ext.v2.acl_policy import Decision
        value = dict(parent=Decision('rw', '/', False), dir_id=DIR, scanned_count=2, next_start=2,
                     items=[(dirent('sub', 'dir'), '/docs/sub', 'dir', 'r'), (dirent('a.txt'), '/docs/a.txt', 'file', 'rw')])
        value.update(kwargs)
        return value

    def setUp(self):
        import seaserv
        import seahub.api2.endpoints.dir  # noqa: F401 -- patch targets below
        repo = patch.object(seaserv.seafile_api, 'get_repo', return_value=SimpleNamespace(id=RID))
        repo.start()
        self.addCleanup(repo.stop)
        authority = patch('cloudfile_ext.v2.directory_page.Authority')
        self.authority = authority.start()
        self.addCleanup(authority.stop)
        throttle = patch('seahub.api2.endpoints.dir.DirView.throttle_classes', ())
        throttle.start()
        self.addCleanup(throttle.stop)

    def test_page_matches_the_eap_fast_path_contract(self):
        self.authority.return_value.page.return_value = self.page()
        tags = [dict(tag_status='OK', tags=[]), dict(tag_status='OK', tags=[
            dict(source='repo', file_tag_id=1, repo_tag_id=7, tag_name='review', tag_color='#abc')])]
        with patch('cloudfile_ext.v2.tag_http.page_tags', return_value=tags) as read:
            result = self.request(dict(p='/docs', start='0', limit='2', with_display_metadata='true'))
        read.assert_called_once_with(RID, self.page()['items'])
        self.assertEqual(result.status_code, 200)
        self.authority.return_value.page.assert_called_once_with(RID, '/docs', start=0, limit=2, if_dir_id=None)
        data = result.data
        self.assertEqual((data['acl_enforced'], data['has_more'], data['next_start'], data['dir_id'], data['user_perm']),
                         (True, True, 2, DIR, 'rw'))
        self.assertEqual([(d['type'], d['name'], d['permission'], d['id']) for d in data['dirent_list']],
                         [('dir', 'sub', 'r', 'c' * 40), ('file', 'a.txt', 'rw', 'c' * 40)])
        self.assertEqual(data['dirent_list'][1]['size'], 7)
        self.assertNotIn('size', data['dirent_list'][0])
        self.assertEqual(result['Cache-Control'], 'no-store')
        self.assertNotIn('tag_batch', data)
        self.assertEqual(data['dirent_list'][0]['tags'], [])
        self.assertEqual(data['dirent_list'][1]['tags'], tags[1]['tags'])
        self.assertEqual([item['tag_status'] for item in data['dirent_list']], ['OK', 'OK'])

    def test_tag_failure_keeps_authorized_page_and_unknown_tags(self):
        self.authority.return_value.page.return_value = self.page()
        with patch('cloudfile_ext.v2.tag_http.read_tags', side_effect=OSError()), \
                self.assertLogs('cloudfile_ext.v2.tag_http', level='ERROR'):
            result = self.request(dict(p='/docs', start='0', limit='2', with_display_metadata='true'))
        self.assertEqual(result.status_code, 200)
        self.assertEqual([(item['tag_status'], item['tags']) for item in result.data['dirent_list']],
                         [('FAILED', None), ('FAILED', None)])
        self.assertNotIn('tag_batch', result.data)

    def test_empty_authorized_page_never_reads_tags(self):
        self.authority.return_value.page.return_value = self.page(items=[], next_start=2)
        with patch('cloudfile_ext.v2.tag_http.read_tags') as read:
            read.return_value = {}
            result = self.request(dict(p='/docs', start='0', limit='2', with_display_metadata='true'))
        read.assert_called_once_with(RID, [])
        self.assertEqual(result.data['dirent_list'], [])
        self.assertTrue(result.data['has_more'])

    def test_last_and_empty_visible_pages(self):
        self.authority.return_value.page.return_value = self.page(items=[], next_start=None, scanned_count=1)
        data = self.request(dict(p='/docs', start='200', limit='200', if_dir_id=DIR)).data
        self.assertEqual((data['dirent_list'], data['has_more'], data['next_start'], data['scan_exhausted']),
                         ([], False, None, True))
        self.authority.return_value.page.return_value = self.page(items=[], next_start=400, scanned_count=200)
        data = self.request(dict(p='/docs', start='200', limit='200', if_dir_id=DIR)).data
        self.assertEqual((data['dirent_list'], data['has_more'], data['next_start']), ([], True, 400))

    def test_failures_keep_their_meaning(self):
        cases = ((DirectoryChanged(), 409), (PermissionError(), 403), (FileNotFoundError(), 404),
                 (ACLUnavailable(), 503), (RuntimeError('rpc'), 503), (PolicyError('bad'), 400))
        for error, code in cases:
            self.authority.return_value.page.side_effect = error
            with self.assertLogs('cloudfile_ext.v2.directory_page', 'ERROR') if code == 503 else _quiet():
                self.assertEqual(self.request(dict(p='/docs', start='0', limit='50')).status_code, code, error)

    def test_invalid_page_arguments_are_rejected_before_authorization(self):
        for params in (dict(limit='0'), dict(limit='501'), dict(start='x'), dict(limit='50', recursive='1'),
                       dict(limit='50', with_parents='true'), dict(limit='50', t='f'),
                       dict(limit='50', with_thumbnail='true'), dict(limit='50', if_dir_id='HEAD')):
            self.assertEqual(self.request(dict(p='/docs', **params)).status_code, 400, params)
        self.authority.assert_not_called()

    def test_unpaged_request_keeps_the_ce_path(self):
        with patch('cloudfile_ext.v2.directory_page.directory_page') as paged, \
                patch('seahub.api2.endpoints.dir.seafile_api') as api:
            api.get_repo.return_value = None
            self.assertEqual(self.request(dict(p='/docs')).status_code, 404)
        paged.assert_not_called()
        self.authority.assert_not_called()


class _quiet:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
