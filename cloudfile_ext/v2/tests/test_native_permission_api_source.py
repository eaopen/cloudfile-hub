"""Cheap source-level API boundary checks when Seahub/Django is unavailable.

Real CE authentication, native RPC and database integration are separate
release gates. These checks prevent accidental omission of the B endpoint's
existing management guard or rerouting directory ACL to another store.
"""
import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
HTTP = ROOT / 'cloudfile_ext/v2/acl_http.py'
URLS = ROOT / 'seahub/urls.py'
GRANTS = ROOT / 'cloudfile_ext/v2/native_grants.py'


class NativePermissionAPISourceTests(unittest.TestCase):
    def test_library_grants_methods_use_existing_ce_management_guard(self):
        tree = ast.parse(HTTP.read_text(encoding='utf-8'))
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                   and n.name == 'LibraryGrants')
        methods = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}
        self.assertTrue({'get', 'put', 'delete', '_write'} <= methods.keys())
        for name in ('get', '_write'):
            names = [n.func.id for n in ast.walk(methods[name])
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
            self.assertIn('require_repo_manage', names, name)
        self.assertIn('AuthenticatedACL', [n.id for n in cls.bases
                                          if isinstance(n, ast.Name)])
        guard = methods.get('_require_native_share_role')
        self.assertIsNotNone(guard)
        self.assertIn('can_share_repo', ast.unparse(guard))
        for name in ('get', '_write'):
            self.assertIn('_require_native_share_role', ast.unparse(methods[name]))
        self.assertIn("native_permission(data['permission'])", ast.unparse(methods['_write']))

    def test_uses_separate_ce_library_and_existing_directory_rule_routes(self):
        url_text = URLS.read_text(encoding='utf-8')
        self.assertIn("authorization/v1/library-grants/', LibraryGrants.as_view()", url_text)
        self.assertIn("authorization/v1/directory-rules/', DirectoryRules.as_view()", url_text)
        self.assertIn("authorization/v1/library-acl-batch/', LibraryACLBatch.as_view()", url_text)
        core = GRANTS.read_text(encoding='utf-8')
        self.assertIn('share_repo(', core)
        self.assertIn('set_group_repo(', core)
        self.assertNotIn('CREATE TABLE', core)
        self.assertNotIn('cf_managed_library', core)


if __name__ == '__main__':
    unittest.main()
