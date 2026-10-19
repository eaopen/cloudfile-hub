"""Signing-time ACL tests; file bytes and expiry are covered by native tests."""
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from cloudfile_ext.v2.downloads import file_download_response
from cloudfile_ext.v2.acl_runtime import ACLUnavailable

RID = '11111111-1111-4111-8111-111111111111'


class DownloadTests(TestCase):
    def request(self, path='/shared/a +文档.xlsx', *, allowed=True, once=False,
                error=None, origin='http://files.example/cfhttp'):
        req = SimpleNamespace(user=SimpleNamespace(username='ordinary@auth.local'))
        with patch('cloudfile_ext.v2.downloads.Authority') as authority, \
                patch('cloudfile_ext.v2.downloads.seafile_api.get_scoped_file_download_token') as mint, \
                patch('cloudfile_ext.v2.downloads.gen_file_get_url',
                      side_effect=lambda token, name: origin + '/files/' + token + '/' + name):
            authority.return_value.effective.return_value.can_read = allowed
            if error:
                authority.side_effect = error
            mint.return_value = dict(token='native-ticket', file_id='a' * 40, expires_in=3600)
            response = file_download_response(req, RID, path, once)
            if response.status_code == 200:
                authority.assert_called_once_with('ordinary@auth.local')
                authority.return_value.effective.assert_called_once_with(RID, path, 'file')
                mint.assert_called_once_with(RID, path, 'ordinary@auth.local', once)
            else:
                mint.assert_not_called()
            return response

    def test_current_user_read_grant_keeps_native_lifetime_and_both_schemes(self):
        for scheme in ('http', 'https'):
            reply = self.request(origin=scheme + '://files.example/cfhttp')
            self.assertEqual(reply.status_code, 200)
            self.assertTrue(json.loads(reply.content).startswith(scheme + '://'))
            self.assertEqual(reply['oid'], 'a' * 40)
            self.assertEqual(reply['X-CloudFile-Download-TTL'], '3600')
            self.assertEqual(reply['Cache-Control'], 'no-store')

    def test_legacy_onetime_option_is_preserved_for_other_callers(self):
        self.assertEqual(self.request(once=True).status_code, 200)

    def test_denied_path_never_mints_a_ticket(self):
        self.assertEqual(self.request(allowed=False).status_code, 403)

    def test_policy_outage_is_not_an_unscoped_fallback(self):
        self.assertEqual(self.request(error=ACLUnavailable()).status_code, 503)

    def test_noncanonical_paths_are_rejected_before_authorization(self):
        for path in ('/', 'relative', '/a/../secret', '/a//b', '/a\\b', '/a\n.txt'):
            self.assertEqual(self.request(path).status_code, 400)


class NativeDispatchCompatibilityTests(TestCase):
    """Execute the selected native FileView method, without copying its logic."""

    def dispatch(self, query):
        import ast
        import os
        from pathlib import Path
        import seahub
        from unittest.mock import Mock
        from rest_framework import status
        source = Path(next(iter(seahub.__path__))) / 'api2/views.py'
        tree = ast.parse(source.read_text())
        view = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                    and node.name == 'FileView')
        method = next(node for node in view.body if isinstance(node, ast.FunctionDef)
                      and node.name == 'get')
        api = Mock()
        api.get_file_id_by_path.return_value = 'f' * 40
        native = Mock(return_value='native-history-response')
        request = SimpleNamespace(GET=query, user=SimpleNamespace(username='ordinary'))
        env = dict(os=os, status=status, seafile_api=api, SearpcError=RuntimeError,
            get_repo=lambda repo: SimpleNamespace(is_virtual=False),
            check_folder_permission=lambda *args: 'rw', send_file_access_msg=Mock(),
            get_repo_file=native)
        exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), 'exec'), env)
        from cloudfile_ext.v2 import downloads
        with patch.object(downloads, 'file_download_response', return_value=SimpleNamespace(status_code=200)) as scoped:
            result = env['get'](object(), request, RID)
        return result, request, scoped, native

    def test_root_relative_native_path_is_canonical_before_issuance(self):
        # Older native clients omit the leading slash; authorization must still
        # receive exactly one canonical path, without weakening path validation.
        _, request, scoped, native = self.dispatch({'p': 'docs/a +文档.pdf', 'reuse': '1'})
        scoped.assert_called_once_with(request, RID, '/docs/a +文档.pdf', False)
        native.assert_not_called()

    def test_history_request_never_mints_a_current_file_grant(self):
        # A commit-bound request retains the original history path rather than
        # acquiring a reusable grant for the current object at the same path.
        result, _, scoped, native = self.dispatch({'p': '/docs/old.pdf', 'commit_id': 'a' * 40})
        self.assertEqual(result, 'native-history-response')
        scoped.assert_not_called()
        native.assert_called_once()
