"""Search runtime security checks in the native Django environment."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from django.core import signing
from rest_framework.test import APIRequestFactory, force_authenticate
from cloudfile_ext.v2.search.client import SearchUnavailable
from cloudfile_ext.v2.search.http import SearchQuery
from cloudfile_ext.v2.search.runtime import AccessDenied, NativeAuthority

RID = 'a6fbc97c-1000-4000-8000-010101010101'
ITEM = dict(repo_id=RID, path='/A/file.txt', kind='file', size=15, mtime=100, tags=[], matched_tags=[])


class SearchHttpTests(TestCase):
    def call(self, params=None, user='native@auth.local', authority=None, client=None):
        request = APIRequestFactory().get('/api/v2.1/cloudfile/search/', params or {'repo_id': RID, 'q': 'file'})
        if user:
            force_authenticate(request, SimpleNamespace(id=user, username=user, is_authenticated=True))
        authority = authority or Mock(version='a'*64, snapshot={'head': 'b'*40}, assert_current=Mock())
        if client is None:
            client = Mock()
            client.page.return_value = [dict(repo_id=RID, path='/A/file.txt', kind='file')]
            authority.resolve.return_value = [ITEM]
        with patch('cloudfile_ext.v2.search.http.NativeAuthority', return_value=authority), \
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
        authority = Mock(version='a'*64, snapshot={'head': 'b'*40}, assert_current=Mock())
        authority.assert_current.side_effect = AccessDenied()
        response, _, _ = self.call(authority=authority)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('data', response.data)

    def test_optional_filters_narrow_existing_get_without_breaking_default(self):
        response, authority, client = self.call(dict(repo_id=RID, q='file',
            kind='file', extension='.TXT', tag='工艺'))
        self.assertEqual(response.status_code, 200)
        client.page.assert_called_once_with(RID, '/', 'file', 0, 51,
                                            kind='file', extension='txt', tag='工艺')
        self.assertEqual(response.data['data'], [])
        # The mock returns ITEM without current native Tag; no stale filtered hit leaks.
        authority.assert_current.assert_called_once_with([])

    def test_matching_native_tag_survives_explicit_filter(self):
        authority = Mock(version='a'*64, snapshot={'head': 'b'*40}, assert_current=Mock())
        authority.resolve.return_value = [dict(ITEM, tags=['工艺'])]
        client = Mock()
        client.page.return_value = [dict(repo_id=RID, path=ITEM['path'], kind='file')]
        response, _, client = self.call(dict(repo_id=RID, q='file', kind='file',
                                             extension='TXT', tag='工艺'),
                                        authority=authority, client=client)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['data']), 1)
        self.assertEqual(response.data['data'][0]['tags'], ['工艺'])
        self.assertEqual(client.page.call_args.kwargs['extension'], 'txt')

    def test_invalid_filter_or_dir_extension_is_rejected_before_search(self):
        for filters in ({'kind': 'admin'}, {'extension': '../pdf'},
                        {'tag': ' 工艺'}, {'kind': 'dir', 'extension': 'pdf'},
                        {'tag': ''}, {'extension': ''}):
            response, _, client = self.call(dict(repo_id=RID, q='file', **filters))
            self.assertEqual(response.status_code, 400)
            client.page.assert_not_called()

    def test_signed_cursor_cannot_change_requested_tag(self):
        from django.core import signing
        binding = dict(user='native@auth.local', repo=RID, q='file', root='/',
                       limit=50, version='a'*64,
                       filters=dict(kind=None, extension=None, tag='工艺'))
        signed = signing.dumps(dict(scope=binding, offset=50),
                               salt='cloudfile-v2-search')
        response, _, client = self.call(dict(repo_id=RID, q='file', cursor=signed, tag='其他'))
        self.assertEqual(response.status_code, 400)
        client.page.assert_not_called()

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


class NativeAuthorityTests(TestCase):
    def authority(self):
        authority = NativeAuthority.__new__(NativeAuthority)
        authority.username, authority.repo_id = 'user', RID
        authority.snapshot = {'acl_rules': [('/A', 'revision')]}
        return authority

    def test_unwired_directory_rules_mask_the_exact_subtree_only(self):
        refs = [dict(ITEM, path='/A/file.txt'), dict(ITEM, path='/AB/file.txt')]
        with patch('cloudfile_ext.v2.search.runtime.native_tags', return_value={r['path']: [] for r in refs}), \
                patch('cloudfile_ext.v2.search.runtime.seafile_api') as native:
            native.check_permission_by_path.return_value = 'r'
            native.get_dirent_by_path.return_value = SimpleNamespace(mode=0o100644, size=15, mtime=100)
            result = self.authority().resolve(refs)
        self.assertIsNone(result[0])
        self.assertEqual(result[1]['path'], '/AB/file.txt')
        self.assertEqual(native.check_permission_by_path.call_count, 1)

    def test_current_native_denial_and_missing_object_hide_results(self):
        authority = self.authority()
        authority.snapshot['acl_rules'] = []
        with patch('cloudfile_ext.v2.search.runtime.native_tags', return_value={ITEM['path']: []}), \
                patch('cloudfile_ext.v2.search.runtime.seafile_api') as native:
            native.check_permission_by_path.return_value = None
            self.assertEqual(authority.resolve([ITEM]), [None])
            native.get_dirent_by_path.assert_not_called()
            native.check_permission_by_path.return_value = 'r'
            native.get_dirent_by_path.return_value = None
            self.assertEqual(authority.resolve([ITEM]), [None])

    def test_removed_tag_cannot_publish_a_stale_tag_only_match(self):
        authority = self.authority()
        authority.snapshot['acl_rules'] = []
        with patch('cloudfile_ext.v2.search.runtime.native_tags', return_value={ITEM['path']: []}), \
                patch('cloudfile_ext.v2.search.runtime.seafile_api') as native:
            native.check_permission_by_path.return_value = 'r'
            native.get_dirent_by_path.return_value = SimpleNamespace(mode=0o100644, size=15, mtime=100)
            self.assertEqual(authority.resolve([dict(ITEM, text_match=False, matched_tags=['removed'])]), [None])
