"""Native entry, shared-root and bounded cache regressions; no native service I/O."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from django.core.cache import cache

from cloudfile_ext.v2.acl_policy import Principal, Rule
from cloudfile_ext.v2.acl_runtime import ACLUnavailable, Authority

RID = '11111111-1111-4111-8111-111111111111'


class CurrentAuthorityTests(unittest.TestCase):
    def test_cached_grant_expires_after_revocation(self):
        cache.clear()
        self.addCleanup(cache.clear)
        api = Mock()
        api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=1)
        api.get_repo_status.return_value = 0
        api.check_permission.return_value = 'r'
        rules = Mock()
        rules.library.return_value = (Rule(RID, '/A', 'test', 'user', 'user', 'u', 'rw'),)
        args = dict(principal=Principal('test', 'u'), rules=rules, api=api)
        with patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=180), \
                patch('cloudfile_ext.v2.library_cache.time.time', return_value=1000) as clock:
            self.assertTrue(Authority('native', **args).effective(RID, '/A').can_write)
            rules.library.return_value = (Rule(RID, '/A', 'test', 'user', 'user', 'u', 'invisible'),)
            # Deliberately leave the shared cache uninvalidated, as can happen
            # between SQL commit and its post-commit invalidation callback.
            self.assertTrue(Authority('native', **args).effective(RID, '/A').can_write)
            clock.return_value = 1181
            self.assertFalse(Authority('native', **args).effective(RID, '/A').can_read)

    def test_shared_root_never_qualifies_root_or_sibling(self):
        api = Mock()
        api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=1)
        api.get_repo_status.return_value = 0
        api.check_permission.return_value = None
        rules = Mock()
        rules.library.return_value = (Rule(RID, '/A', 'test', 'user', 'user', 'u', 'rw', True, True),)
        authority = Authority('native', principal=Principal('test', 'u'), rules=rules, api=api)
        self.assertTrue(authority.effective(RID, '/A/file', 'file').can_write)
        for path in ('/', '/B', '/AB'):
            self.assertFalse(authority.effective(RID, path).can_read)


class NativeRequestFailureTests(unittest.TestCase):
    def test_outage_is_marked_but_denial_is_not(self):
        # Execute the real, small upstream adapter without booting Seahub/RPC.
        source = Path(__file__).resolve().parents[3] / 'seahub/views/__init__.py'
        node = next(n for n in ast.parse(source.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == '_cloudfile_path_permission')
        mark, gate = Mock(), Mock()
        namespace = dict(_cf_mark_permission_unavailable=mark, _cf_check_permission=gate)
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
        request = SimpleNamespace(user=SimpleNamespace(username='native'))
        call = namespace['_cloudfile_path_permission']
        gate.side_effect = ACLUnavailable('offline')
        self.assertIsNone(call(request, RID, '/A', 'rw'))
        mark.assert_called_once_with(request)
        mark.reset_mock()
        gate.side_effect = None
        gate.return_value = None
        self.assertIsNone(call(request, RID, '/A', 'rw'))
        mark.assert_not_called()

    def test_existing_middleware_reports_marked_denial_as_503(self):
        from django.http import JsonResponse
        from cloudfile_extensions.permission_middleware import (
            CloudFilePermissionMiddleware, mark_permission_unavailable)
        request = SimpleNamespace()
        middleware = CloudFilePermissionMiddleware(lambda request: JsonResponse({}, status=403))
        self.assertEqual(middleware(request).status_code, 403)
        mark_permission_unavailable(request)
        result = middleware(request)
        self.assertEqual(result.status_code, 503)
        self.assertIn('no-store', result['Cache-Control'])
