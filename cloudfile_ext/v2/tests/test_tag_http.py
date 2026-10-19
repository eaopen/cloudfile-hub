"""V2 tag read contract: authorize before two-query batch, no fake empty tags."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch, Mock

from rest_framework.test import APIRequestFactory, force_authenticate
from django.conf import settings

from cloudfile_ext.v2.tag_http import TagBatch, batch_tags, page_tags, VERSION, MODEL

RID = '00000000-0000-4000-8000-000000000001'


def ref(path, is_dir=False):
    return dict(path=path, is_dir=is_dir)


class TagBatchTests(TestCase):
    def session_request(self, *, csrf=True, extra=''):
        # Exercise the real SessionAuthentication/CSRF path; force_authenticate
        # bypasses the parser interaction that caused the live browser HTTP500.
        token = 'a' * 32
        raw = APIRequestFactory(enforce_csrf_checks=True).post(
            '/api/v2.1/cloudfile/tags/batch/',
            dict(version=VERSION, repo_id=RID, items=[ref('/docs/file' + extra)]),
            format='json', **({'HTTP_X_CSRFTOKEN': token} if csrf else {}))
        raw.user = SimpleNamespace(username='current', is_authenticated=True, is_active=True)
        raw.COOKIES[settings.CSRF_COOKIE_NAME] = token
        return TagBatch.as_view()(raw)

    def test_browser_session_json_body_survives_native_csrf_check(self):
        with patch('cloudfile_ext.v2.tag_http.batch_tags', return_value={'items': []}) as tags:
            response = self.session_request()
        self.assertEqual(response.status_code, 200)
        tags.assert_called_once_with('current', RID, [('/docs/file', 'file')])

    def test_body_cache_does_not_bypass_csrf_or_size_limit(self):
        with patch('cloudfile_ext.v2.tag_http.batch_tags') as tags:
            self.assertEqual(self.session_request(csrf=False).status_code, 403)
            oversized = self.session_request(extra='x' * 65536)
            self.assertEqual(oversized.status_code, 400)
            self.assertEqual(oversized.data['code'], 'INVALID_TAG_BATCH')
        tags.assert_not_called()

    def request(self, method='post', data=None, authenticated=True):
        factory = APIRequestFactory()
        raw = (factory.post('/api/v2.1/cloudfile/tags/batch/', data or {}, format='json')
               if method == 'post' else factory.get('/api/v2.1/cloudfile/tags/batch/', data or {}))
        if authenticated:
            force_authenticate(raw, SimpleNamespace(username='current', is_authenticated=True, is_active=True))
        return TagBatch.as_view()(raw)

    def test_capabilities_require_login_and_do_not_accept_extra_params(self):
        self.assertIn(self.request(method='get', authenticated=False).status_code, (401, 403))
        result = self.request(method='get')
        self.assertEqual(result.status_code, 200)
        self.assertEqual((result.data['version'], result.data['model']), (VERSION, MODEL))
        self.assertEqual((result.data['max_items'], result.data['max_bytes']), (200, 65536))
        self.assertEqual(result['Cache-Control'], 'no-store')
        self.assertEqual(self.request(method='get', data=dict(username='another')).status_code, 400)

    def test_batch_keeps_order_mixed_native_tag_sources_and_no_hidden_sql(self):
        auth = Mock()
        auth.effective.side_effect = lambda repo, path, kind: SimpleNamespace(can_read=path != '/docs/private')
        auth.api.get_dirent_by_path.side_effect = lambda repo, path: (
            None if path == '/docs/missing' else SimpleNamespace(mode=0o040755 if path == '/docs/sub' else 0o100644))
        tags = {('/docs/file', 'file'): [dict(source='repo', file_tag_id=2, repo_tag_id=5,
                                                  tag_name='SYS_DESIGN', tag_color='#abc'),
                                         dict(source='legacy', legacy_tag_id=3, tag_name='草稿', read_only=True)],
                ('/docs/sub', 'dir'): []}
        body = dict(version=VERSION, repo_id=RID, items=[ref('/docs/file'), ref('/docs/private'),
                                                          ref('/docs/sub', True), ref('/docs/missing'),
                                                          ref('/docs/file')])
        with patch('cloudfile_ext.v2.tag_http.Authority', return_value=auth) as acl, \
                patch('cloudfile_ext.v2.tag_http.read_tags', return_value=tags) as read:
            response = self.request(data=body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['model'], MODEL)
        self.assertEqual([x['status'] for x in response.data['items']],
                         ['OK', 'DENIED', 'OK', 'NOT_FOUND', 'OK'])
        self.assertEqual([x['source'] for x in response.data['items'][0]['tags']], ['repo', 'legacy'])
        self.assertEqual(response.data['items'][2]['tags'], [])
        self.assertIsNone(response.data['items'][1]['tags'])
        self.assertIsNone(response.data['items'][3]['tags'])
        acl.assert_called_once_with('current')
        self.assertEqual(auth.effective.call_count, 4)
        self.assertEqual(auth.api.get_dirent_by_path.call_count, 3)
        read.assert_called_once_with(RID, [('/docs/file', 'file'), ('/docs/sub', 'dir')])

    def test_invalid_body_never_reads_tags(self):
        cases = [dict(version=1, repo_id=RID, items=[ref('/docs/file')]),
                 dict(version=VERSION, repo_id='repo', items=[ref('/docs/file')]),
                 dict(version=VERSION, repo_id=RID, items=[ref('/')]),
                 dict(version=VERSION, repo_id=RID, items=[ref('/a', 'false')]),
                 dict(version=VERSION, repo_id=RID, items=[]),
                 dict(version=VERSION, repo_id=RID, items=[ref('/a')]*201),
                 dict(version=VERSION, repo_id=RID, items=[ref('/x/../y')])]
        with patch('cloudfile_ext.v2.tag_http.Authority') as acl:
            for body in cases:
                self.assertEqual(self.request(data=body).status_code, 400)
            acl.assert_not_called()

    def test_acl_failure_does_not_become_empty_tags(self):
        body = dict(version=VERSION, repo_id=RID, items=[ref('/docs/a')])
        with patch('cloudfile_ext.v2.tag_http.Authority', side_effect=OSError('acl failure')), \
                patch('cloudfile_ext.v2.tag_http.read_tags') as read, \
                self.assertLogs('cloudfile_ext.v2.tag_http', level='ERROR'):
            response = self.request(data=body)
        self.assertEqual(response.status_code, 503)
        read.assert_not_called()

    def test_tag_sql_error_is_unavailable_not_successful_empty(self):
        body = dict(version=VERSION, repo_id=RID, items=[ref('/docs/a')])
        auth = Mock()
        auth.effective.return_value.can_read = True
        auth.api.get_dirent_by_path.return_value = SimpleNamespace(mode=0o100644)
        with patch('cloudfile_ext.v2.tag_http.Authority', return_value=auth), \
                patch('cloudfile_ext.v2.tag_http.read_tags', side_effect=OSError()), \
                self.assertLogs('cloudfile_ext.v2.tag_http', level='ERROR'):
            response = self.request(data=body)
        self.assertEqual(response.status_code, 503)

    def test_inline_uses_only_existing_authorized_page(self):
        entry = SimpleNamespace(obj_name='file', mode=0o100644)
        entries = [(entry, '/docs/file', 'file', 'r')]
        with patch('cloudfile_ext.v2.tag_http.read_tags', return_value={('/docs/file', 'file'): []}) as tags:
            result = page_tags(RID, entries)
        self.assertEqual(result, [dict(tag_status='OK', tags=[])])
        tags.assert_called_once_with(RID, [('/docs/file', 'file')])
        with patch('cloudfile_ext.v2.tag_http.read_tags', side_effect=OSError()), \
                self.assertLogs('cloudfile_ext.v2.tag_http', level='ERROR'):
            result = page_tags(RID, entries)
        self.assertEqual(result[0]['tag_status'], 'FAILED')
        self.assertIsNone(result[0]['tags'])
