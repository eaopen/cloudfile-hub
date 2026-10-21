"""Prevent old managed-library routing, ledgers and unsafe ACL fallbacks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]

class NoManagedLibraryRegression(unittest.TestCase):
    def test_removed_routes_and_models(self):
        for name in ('cloudfile_ext/sso/library_shares.py',
                     'cloudfile_ext/sso/library_share_policy.py',
                     'cloudfile_ext/sso/library_share_service.py'):
            self.assertFalse((ROOT / name).exists(), name)
        urls = (ROOT / 'cloudfile_ext/sso/__init__.py').read_text()
        self.assertNotIn('AdminLibrarySharesDesiredView', urls)
        self.assertNotIn('cloudfile-admin-library-shares-status', urls)
        api = (ROOT / 'cloudfile_ext/sso/apis.py').read_text()
        self.assertNotIn('ManagedLibraryShare', api)
        self.assertNotIn('AdminLibrarySharesReconcileView', api)

    def test_retired_extension_tree_is_absent(self):
        # Old CloudFile V0.x resources, session and share ledgers are not an
        # alternative runtime; prevent the entire package being copied back.
        self.assertFalse((ROOT / 'cloudfile_extensions').exists())

    def test_current_runtime_has_no_enrollment_sql(self):
        for module in (ROOT / 'cloudfile_ext/v2').rglob('*.py'):
            if module.name.startswith('test_'):
                continue
            source = module.read_text(encoding='utf-8')
            with self.subTest(module=str(module.relative_to(ROOT))):
                self.assertNotIn('INSERT INTO cf_managed_library(', source)
                self.assertNotIn('FROM cf_managed_library ', source)
                self.assertNotIn('cf_library_share_revision', source)
                self.assertNotIn('managed library', source.lower())

    def test_native_errors_never_restore_ce_permission(self):
        source = (ROOT / 'cloudfile_ext/v2/native_gate.py').read_text()
        start = source.index('    except Exception:', source.index('def check_permission('))
        end = source.index('    if not decision.can_read:', start)
        self.assertIn('return None', source[start:end])
        self.assertNotIn('return permission', source[start:end])
        rule = (ROOT / 'cloudfile_ext/v2/tests/test_native_gate.py').read_text()
        self.assertIn('test_runtime_error_refuses_native_fallback', rule)

    def test_internal_batch_is_path_qualified_not_repo_mode(self):
        api = (ROOT / 'cloudfile_ext/v2/acl_http.py').read_text()
        self.assertIn("partial = data.get('partial') is True", api)
        self.assertIn('permissions.append(None)', api)
        self.assertIn('raise PermissionError()', api)
        self.assertIn('authority.effective(data', api)

if __name__ == '__main__':
    unittest.main()
