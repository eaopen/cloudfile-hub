"""Exercise the deployed compatibility methods with real V2 policy resolution."""
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_ext.v2.acl_policy import Principal, Rule
from cloudfile_ext.v2.acl_runtime import Authority, ACLUnavailable

RID = '11111111-1111-4111-8111-111111111111'
ROOT = Path(__file__).resolve().parents[3]


class CookieNativeRouteTests(TestCase):
    def setUp(self):
        # Isolate only CE imports; compile the actual compatibility class, so a
        # regression to the old provider fails instead of testing a copied view.
        tree = ast.parse((ROOT / 'cloudfile_extensions/authorization/native_http.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeRepoView')
        scope = {'RepoView': type('RepoView', (), {})}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT), 'exec'), scope)
        self.view = scope['NativeRepoView']()
        self.api = Mock()
        self.api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=1,
            name='Library', size=5, encrypted=False, status=0, repo_type='repo')
        self.api.get_repo_status.return_value = 0
        self.api.get_repo_owner.return_value = 'owner'
        self.api.check_permission.return_value = 'rw'
        self.rules = Mock()
        self.rules.library.return_value = []

    def call(self, *, staff=False, manager=False, error=None):
        user = SimpleNamespace(username='member', is_staff=staff,
            admin_permissions=SimpleNamespace(can_manage_library=lambda: staff))
        authority = Authority('member', principal=Principal('etech', 'uid'),
                              rules=self.rules, api=self.api)
        with patch('cloudfile_ext.v2.acl_runtime.Authority', return_value=authority,
                   side_effect=error), \
             patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=0), \
             patch('seahub.share.utils.is_repo_admin', return_value=manager):
            return self.view.get(SimpleNamespace(user=user), RID)

    def test_cookie_metadata_uses_v2_without_legacy_directory(self):
        result = self.call(manager=True)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['permission'], 'rw')
        self.assertEqual(result.data['user_perm'], 'rw')
        self.assertFalse(result.data['is_admin'])
        self.assertTrue(result.data['can_manage'])
        self.assertEqual(result['Cache-Control'], 'no-store')

    def test_native_readonly_and_v2_deny_are_not_widened(self):
        self.api.check_permission.return_value = 'r'
        self.assertEqual(self.call().data['permission'], 'r')
        self.rules.library.return_value = [Rule(RID, '/', 'etech', 'user', 'user', 'uid', 'invisible')]
        self.assertEqual(self.call(staff=True).status_code, 403)

    def test_native_denial_and_outage_never_become_access(self):
        self.api.check_permission.return_value = None
        self.assertEqual(self.call(staff=True).status_code, 403)
        self.assertEqual(self.call(error=ACLUnavailable()).status_code, 503)
        self.api.check_permission.side_effect = RuntimeError('RPC unavailable')
        self.assertEqual(self.call().status_code, 503)

    def test_file_route_inherits_current_native_download_guard(self):
        tree = ast.parse((ROOT / 'cloudfile_extensions/authorization/native_file_http.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.ClassDef))
        native = type('FileView', (), {'get': lambda *args: 'guarded'})
        scope = {'FileView': native}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT), 'exec'), scope)
        self.assertIs(scope['NativeFileView'].get, native.get)

    def test_v2_directory_blocks_legacy_background_and_login_writes(self):
        # Execute the real entry points with an intentionally unusable legacy
        # registry: neither directory lookup nor native writes may be reached.
        tree = ast.parse((ROOT / 'cloudfile_ext/sso/service.py').read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name in ('sync', 'sync_user')]
        record = Mock(return_value='skipped')
        scope = {'_settings': lambda: SimpleNamespace(CF_DIRECTORY_URL='https://directory.test'),
                 '_record': record, 'STATUS_SKIPPED': 'skipped'}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(ROOT), 'exec'), scope)
        self.assertEqual(scope['sync'](registry=object()), 'skipped')
        self.assertIsNone(scope['sync_user']('member', registry=object()))
        record.assert_called_once()
