"""Search runtime security checks in the native Django environment."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from django.core import signing
from rest_framework.test import APIRequestFactory, force_authenticate
from cloudfile_ext.v2.search.client import SearchUnavailable
from cloudfile_ext.v2.search.http import SearchQuery
from cloudfile_ext.v2.acl_policy import Principal, Rule
from cloudfile_ext.v2.search import acl_filter
from cloudfile_ext.v2.search.runtime import AccessDenied, SearchAuthority

RID = 'a6fbc97c-1000-4000-8000-010101010101'
ITEM = dict(repo_id=RID, path='/A/file.txt', kind='file', size=15, mtime=100, tags=[], matched_tags=[])


class SearchHttpTests(TestCase):
    def setUp(self):
        # Authorization tests should not require an external Redis throttle
        # service: throttle behavior belongs to separate HTTP middleware tests.
        throttle = patch('cloudfile_ext.v2.search.http.SearchQuery.throttle_classes', ())
        throttle.start()
        self.addCleanup(throttle.stop)

    def call(self, params=None, user='native@auth.local', authority=None, client=None):
        request = APIRequestFactory().get('/api/v2.1/cloudfile/search/', params or {'repo_id': RID, 'q': 'file'})
        if user:
            force_authenticate(request, SimpleNamespace(id=user, username=user, is_authenticated=True))
        authority = authority or Mock(version='a'*64, snapshot={'head': 'b'*40}, assert_current=Mock(), filter=None)
        if client is None:
            client = Mock()
            client.page.return_value = [dict(repo_id=RID, path='/A/file.txt', kind='file')]
            authority.resolve.return_value = [ITEM]
        with patch('cloudfile_ext.v2.search.http.SearchAuthority', return_value=authority), \
                patch('cloudfile_ext.v2.search.http.configured_client', return_value=client):
            return SearchQuery.as_view()(request), authority, client

    def test_authenticated_get_matches_existing_eap_contract(self):
        response, authority, client = self.call()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['provider'], 'meilisearch')
        self.assertEqual(response.data['data'][0]['authorization'], dict(repo_id=RID, path=ITEM['path'], kind='file', read=True, visible=True))
        self.assertNotIn('estimatedTotalHits', response.data)
        authority.assert_current.assert_called_once_with([ITEM])

    def test_anonymous_cannot_search(self):
        self.assertIn(self.call(user=None)[0].status_code, (401, 403))

    def test_revocation_discards_prepared_result(self):
        authority = Mock(version='a'*64, snapshot={'head': 'b'*40}, assert_current=Mock(), filter=None)
        authority.assert_current.side_effect = AccessDenied()
        response, _, _ = self.call(authority=authority)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('data', response.data)

    def test_meili_outage_is_503(self):
        client = Mock()
        client.page.side_effect = SearchUnavailable()
        self.assertEqual(self.call(client=client)[0].status_code, 503)

    def test_tampered_or_cross_subject_cursor_is_rejected(self):
        for cursor in ('tampered', signing.dumps({'scope': {'user': 'other'}, 'offset': 1}, salt='cloudfile-v2-search')):
            response, _, client = self.call({'repo_id': RID, 'q': 'file', 'cursor': cursor})
            self.assertEqual(response.status_code, 400)
            client.page.assert_not_called()

    def test_scope_and_limit_are_validated(self):
        for values in ({'path': '/A/../B'}, {'path': '/A//B'}, {'limit': 101}, {'filter': 'repo_id != x'}):
            response, _, client = self.call(dict(repo_id=RID, q='file', **values))
            self.assertEqual(response.status_code, 400)
            client.page.assert_not_called()


    def test_acl_filter_narrows_candidates_and_nothing_skips_the_index(self):
        authority = Mock(version='a'*64, snapshot={'head': 'b'*40}, assert_current=Mock(), filter='(NOT dirs IN ["/S"])')
        response, _, client = self.call(authority=authority)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.page.call_args.kwargs['acl_filter'], '(NOT dirs IN ["/S"])')
        authority = Mock(version='a'*64, snapshot={'head': 'b'*40}, assert_current=Mock(), filter=acl_filter.NOTHING)
        authority.resolve.return_value = []
        response, _, client = self.call(authority=authority, client=Mock())
        self.assertEqual((response.status_code, response.data['data'], response.data['next_cursor']), (200, [], None))
        client.page.assert_not_called()


P = Principal('etech', 'uid')


class SearchAuthorityTests(TestCase):
    """Real V2 Authority with native test doubles; no SQL, cache or Meilisearch."""
    def setUp(self):
        ttl = patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=0)
        ttl.start()
        self.addCleanup(ttl.stop)
        native = patch('cloudfile_ext.v2.search.runtime.seafile_api')
        self.native = native.start()
        self.addCleanup(native.stop)
        self.native.get_repo.return_value = SimpleNamespace(is_virtual=False, encrypted=False, head_cmmt_id='c'*40)
        self.native.get_dirent_by_path.return_value = SimpleNamespace(mode=0o100644, size=15, mtime=100)
        tags = patch('cloudfile_ext.v2.search.runtime.native_tags', side_effect=lambda repo, refs: {r['path']: [] for r in refs})
        tags.start()
        self.addCleanup(tags.stop)
        self.rules = [Rule(RID, '/', 'etech', 'user', 'user', 'uid', 'r'),
                      Rule(RID, '/S', 'etech', 'user', 'user', 'uid', 'invisible')]
        self.base = 'rw'
        self.current_principal = P
        self.authorities = []
        build = patch('cloudfile_ext.v2.search.runtime.Authority', side_effect=self.authority)
        build.start()
        self.addCleanup(build.stop)

    def authority(self, username, principal=None):
        from cloudfile_ext.v2.acl_runtime import Authority
        store = Mock()
        store.library.side_effect = lambda repo: None if self.rules is None else tuple(self.rules)
        store.candidates.side_effect = lambda repo, path, principal: [(r, 'v') for r in self.over_budget if path.startswith(r.path)]
        api = Mock()
        api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=1)
        api.get_repo_status.return_value = 0
        api.check_permission.side_effect = lambda repo, user: self.base
        authority = Authority(username, principal=principal or self.current_principal, rules=store, api=api)
        self.authorities.append(authority)
        return authority

    def test_root_rule_library_is_searchable_and_hidden_subtree_is_filtered(self):
        search = SearchAuthority('user', RID, '/')
        self.assertEqual(search.filter, '(NOT dirs IN ["/S"])')
        refs = [dict(ITEM, path='/A/file.txt'), dict(ITEM, path='/S/file.txt')]
        result = search.resolve(refs)
        self.assertEqual(result[0]['path'], '/A/file.txt')
        self.assertIsNone(result[1])
        self.native.get_dirent_by_path.assert_called_once_with(RID, '/A/file.txt')
        self.native.check_permission_by_path.assert_not_called()

    def test_unreadable_root_and_unmapped_repositories(self):
        with self.assertRaises(AccessDenied):
            SearchAuthority('user', RID, '/S')
        self.native.get_repo.return_value = SimpleNamespace(is_virtual=True, encrypted=False, head_cmmt_id='c'*40)
        with self.assertRaises(SearchUnavailable):
            SearchAuthority('user', RID, '/')
        with patch('cloudfile_ext.v2.search.runtime.Authority', side_effect=PermissionError('inactive account')):
            self.native.get_repo.return_value = SimpleNamespace(is_virtual=False, encrypted=False, head_cmmt_id='c'*40)
            with self.assertRaises(AccessDenied):
                SearchAuthority('user', RID, '/')

    def test_index_candidates_cannot_read_tags_before_native_authorization(self):
        search = SearchAuthority('user', RID, '/')
        references = [dict(ITEM, path='/S/private.txt'),
                      dict(ITEM, path='/A/missing.txt'),
                      dict(ITEM, path='/A/file.txt')]
        def entry(repo_id, path):
            if path == '/A/missing.txt':
                return None
            return SimpleNamespace(mode=0o100644, size=15, mtime=100)
        self.native.get_dirent_by_path.side_effect = entry
        with patch('cloudfile_ext.v2.search.runtime.native_tags',
                   return_value={'/A/file.txt': ['current']}) as tags:
            result = search.resolve(references)
        self.assertEqual([i is not None for i in result], [False, False, True])
        self.assertEqual(result[-1]['tags'], ['current'])
        self.assertEqual([c.args[1] for c in self.native.get_dirent_by_path.call_args_list],
                         ['/A/missing.txt', '/A/file.txt'])
        tags.assert_called_once_with(RID, [references[-1]])

    def test_entirely_denied_batch_never_reads_native_tags(self):
        search = SearchAuthority('user', RID, '/')
        with patch('cloudfile_ext.v2.search.runtime.native_tags') as tags:
            result = search.resolve([dict(ITEM, path='/S/private.txt')])
        self.assertEqual(result, [None])
        tags.assert_not_called()
        self.native.get_dirent_by_path.assert_not_called()

    def test_principal_group_change_and_account_disable_are_rechecked(self):
        search = SearchAuthority('user', RID, '/')
        self.current_principal = Principal('etech', 'uid', frozenset({('role', 'role', 'new')}))
        with self.assertRaises(SearchUnavailable):
            search.assert_current([])
        with patch('cloudfile_ext.v2.search.runtime.Authority',
                   side_effect=PermissionError('native account disabled')):
            with self.assertRaises(AccessDenied):
                search.assert_current([])

    def test_directory_only_share_searches_inside_its_root(self):
        self.base = None
        self.rules = [Rule(RID, '/team', 'etech', 'user', 'user', 'uid', 'r', True, True)]
        with self.assertRaises(AccessDenied):
            SearchAuthority('user', RID, '/')
        search = SearchAuthority('user', RID, '/team')
        self.assertEqual(search.filter, '(dirs IN ["/team"] OR path IN ["/team"])')

    def test_missing_object_and_removed_tag_hide_results(self):
        search = SearchAuthority('user', RID, '/')
        self.native.get_dirent_by_path.return_value = None
        self.assertEqual(search.resolve([ITEM]), [None])
        self.native.get_dirent_by_path.return_value = SimpleNamespace(mode=0o100644, size=15, mtime=100)
        self.assertEqual(search.resolve([dict(ITEM, text_match=False, matched_tags=['removed'])]), [None])

    def test_changed_rules_head_or_grant_invalidate_the_prepared_page(self):
        search = SearchAuthority('user', RID, '/')
        items = search.resolve([ITEM])
        calls = self.native.get_dirent_by_path.call_count
        search.assert_current(items)
        self.assertEqual(self.native.get_dirent_by_path.call_count, calls)
        self.assertIs(self.authorities[-1].principal, search.authority.principal)
        self.rules = self.rules + [Rule(RID, '/A', 'etech', 'user', 'user', 'uid', 'invisible')]
        with self.assertRaises(SearchUnavailable):
            search.assert_current(items)
        self.rules = self.rules[:2]
        self.native.get_repo.return_value = SimpleNamespace(is_virtual=False, encrypted=False, head_cmmt_id='d'*40)
        with self.assertRaises(SearchUnavailable):
            search.assert_current(items)
        self.base = None
        with self.assertRaises(AccessDenied):
            search.assert_current(items)

    def test_over_budget_library_falls_back_to_per_hit_decisions(self):
        self.rules, self.over_budget = None, [Rule(RID, '/S', 'etech', 'user', 'user', 'uid', 'invisible')]
        search = SearchAuthority('user', RID, '/')
        self.assertIsNone(search.filter)
        refs = [dict(ITEM, path='/A/file.txt'), dict(ITEM, path='/S/file.txt')]
        items = [item for item in search.resolve(refs) if item]
        self.assertEqual([item['path'] for item in items], ['/A/file.txt'])
        search.assert_current(items)
        self.native.get_dirent_by_path.return_value = None
        with self.assertRaises(SearchUnavailable):
            search.assert_current(items)
