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

    def _resolve_extension_module(self, name):
        target = ROOT.joinpath(*name.split('.'))
        return target.with_suffix('.py').exists() or (target / '__init__.py').exists()

    def test_live_extension_imports_resolve(self):
        """A module may only be deleted after every live import is rewired.

        The 2026-10-21 wholesale deletion of ``cloudfile_extensions`` left
        ``seahub`` startup imports pointing at missing modules. Resolve every
        in-repo import so a future deletion cannot silently ship a broken Hub.
        """
        import ast

        missing = []
        for base in ('seahub', 'cloudfile_ext'):
            for path in (ROOT / base).rglob('*.py'):
                text = path.read_text(encoding='utf-8')
                if 'cloudfile_extensions' not in text:
                    continue
                try:
                    tree = ast.parse(text)
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom):
                        names = [node.module] if node.module else []
                    elif isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    else:
                        continue
                    for name in names:
                        if not name.startswith('cloudfile_extensions'):
                            continue
                        if not self._resolve_extension_module(name):
                            missing.append('%s: %s' % (path.relative_to(ROOT), name))
        self.assertEqual(missing, [])

    def test_deploy_wired_extension_modules_exist(self):
        # Modules the Docker deployment settings/middleware/gunicorn hooks
        # resolve by name at runtime. Their removal needs a coordinated Docker
        # change, not a one-sided deletion.
        required = (
            'cloudfile_extensions',
            'cloudfile_extensions.root_urls',
            'cloudfile_extensions.permission_middleware',
            'cloudfile_extensions.authorization.browsing',
            'cloudfile_extensions.authorization.global_admin',
            'cloudfile_extensions.authorization.gunicorn',
            'cloudfile_extensions.editing.runtime',
            'cloudfile_extensions.resources.native',
            'cloudfile_extensions.resources.paths',
            'cloudfile_extensions.identity.native_session',
        )
        missing = [name for name in required
                   if not self._resolve_extension_module(name)]
        self.assertEqual(missing, [])

    def test_legacy_extension_test_suite_is_not_a_v2_gate(self):
        self.assertFalse((ROOT / 'cloudfile_extensions/tests').exists())
        self.assertFalse((ROOT / 'cloudfile_extensions/urls.py').exists())

    def test_retired_v08_acl_package_stays_removed(self):
        self.assertFalse((ROOT / 'cloudfile_ext/acl').exists())
        facade = (ROOT / 'cloudfile_ext/permissions.py').read_text()
        self.assertIn('from cloudfile_ext.v2.acl_runtime import Authority', facade)
        self.assertNotIn('from cloudfile_ext.acl import service', facade)

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
