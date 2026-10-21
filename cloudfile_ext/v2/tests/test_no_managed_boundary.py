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

    def test_current_runtime_has_no_enrollment_sql(self):
        for name in ('cloudfile_extensions/authorization/share_service.py',
                     'cloudfile_extensions/authorization/shares.py'):
            source = (ROOT / name).read_text()
            self.assertNotIn('INSERT INTO cf_managed_library(', source, name)
        for module in ('cloudfile_ext/v2/acl_runtime.py',
                       'cloudfile_ext/v2/acl_http.py',
                       'cloudfile_ext/v2/acl_policy.py'):
            text = (ROOT / module).read_text()
            self.assertNotIn('managed library', text.lower(), module)

    def test_native_errors_never_restore_ce_permission(self):
        source = (ROOT / 'cloudfile_ext/v2/native_gate.py').read_text()
        start = source.index('    except Exception:', source.index('def check_permission('))
        end = source.index('    if not decision.can_read:', start)
        self.assertIn('return None', source[start:end])
        self.assertNotIn('return permission', source[start:end])
        rule = (ROOT / 'cloudfile_ext/v2/tests/test_native_gate.py').read_text()
        self.assertIn('test_runtime_error_refuses_native_fallback', rule)

if __name__ == '__main__':
    unittest.main()
