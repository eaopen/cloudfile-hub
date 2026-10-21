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

    def test_all_first_party_absolute_imports_resolve(self):
        """Resolve in-repo imports across native Seahub and both CloudFile trees.

        A removed package must never leave a delayed ImportError in search,
        tags, SSO, API routes or deployed extension hooks. This is a cheap
        syntax/tree check without importing Django or opening databases.
        """
        import ast
        missing = []
        prefixes = ('cloudfile_ext', 'cloudfile_extensions')
        for base in ('seahub', 'cloudfile_ext', 'cloudfile_extensions'):
            directory = ROOT / base
            if not directory.is_dir():
                continue
            for path in directory.rglob('*.py'):
                try:
                    syntax = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
                except SyntaxError as exc:
                    missing.append('%s: syntax error %s' % (path.relative_to(ROOT), exc))
                    continue
                for node in ast.walk(syntax):
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.level == 0:
                        names = [node.module] if node.module else []
                    else:
                        continue
                    for name in names:
                        if not any(name == prefix or name.startswith(prefix + '.')
                                   for prefix in prefixes):
                            continue
                        if not self._resolve_extension_module(name):
                            missing.append('%s: %s' % (path.relative_to(ROOT), name))
        self.assertEqual(missing, [])

    def test_retired_acl_and_search_imports_are_absent(self):
        """No compatibility test may reintroduce the old resolver or snapshot."""
        import ast
        retired = (
            'cloudfile_ext.acl',
            'cloudfile_ext.search.access',
            'cloudfile_ext.search.access_runtime',
            'cloudfile_ext.search.native_many',
            'cloudfile_ext.search.native_transport',
        )
        violations = []
        for base in ('cloudfile_ext', 'seahub', 'cloudfile_extensions'):
            root = ROOT / base
            if not root.exists():
                continue
            for path in root.rglob('*.py'):
                syntax = ast.parse(path.read_text(encoding='utf-8'))
                for node in ast.walk(syntax):
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.level == 0:
                        names = [node.module] if node.module else []
                        # Catch from cloudfile_ext.search import access as well.
                        names.extend('%s.%s' % (node.module, alias.name)
                                     for alias in node.names if node.module)
                    else:
                        continue
                    if any(name == gone or name.startswith(gone + '.')
                           for name in names for gone in retired):
                        violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(violations, [])
        legacy = (ROOT / 'cloudfile_ext/search/bounded_view.py').read_text()
        self.assertIn('from cloudfile_ext.v2.search.http import SearchQuery as BoundedSearch', legacy)

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
            'cloudfile_extensions.resources.paths',
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
        start = source.index('    except Exception as error:', source.index('def check_permission('))
        end = source.index('    if not decision.can_read:', start)
        self.assertIn('raise ACLUnavailable', source[start:end])
        self.assertNotIn('return permission', source[start:end])
        rule = (ROOT / 'cloudfile_ext/v2/tests/test_native_gate.py').read_text()
        self.assertIn('test_runtime_error_refuses_native_fallback', rule)

    def test_internal_batch_is_path_qualified_not_repo_mode(self):
        api = (ROOT / 'cloudfile_ext/v2/acl_http.py').read_text()
        self.assertIn("partial = data.get('partial') is True", api)
        self.assertIn('permissions.append(None)', api)
        self.assertIn('raise PermissionError()', api)
        self.assertIn('authority.effective(data', api)

    def test_retired_authorization_stack_and_relative_imports_stay_removed(self):
        import ast
        forbidden = ('cf_dir_admin', 'cf_policy_request', 'PolicyCore', 'ContentReadAuthority')
        missing = []
        for path in (ROOT / 'cloudfile_extensions').rglob('*.py'):
            source = path.read_text()
            for token in forbidden:
                self.assertNotIn(token, source, str(path))
            package = list(path.relative_to(ROOT).parts[:-1])
            for node in ast.walk(ast.parse(source)):
                if not isinstance(node, ast.ImportFrom) or not node.level:
                    continue
                parts = package[:len(package) - node.level + 1]
                if node.module:
                    parts += node.module.split('.')
                    name = '.'.join(parts)
                    if not self._resolve_extension_module(name): missing.append(name)
                else:
                    for alias in node.names:
                        name = '.'.join(parts + [alias.name])
                        if not self._resolve_extension_module(name): missing.append(name)
        self.assertEqual(missing, [])
        for name in ('authorization/host.py', 'authorization/core.py', 'authorization/rules.py',
                     'authorization/directory_management.py', 'authorization/native_read.py',
                     'authorization/scoped_read.py', 'identity/user_delegation.py',
                     'identity/read_ticket.py', 'identity/native_session.py'):
            self.assertFalse((ROOT / 'cloudfile_extensions' / name).exists(), name)

if __name__ == '__main__':
    unittest.main()
