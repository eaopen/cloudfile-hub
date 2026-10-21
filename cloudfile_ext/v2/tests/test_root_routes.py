"""Current root routing must never load retired schema-dependent endpoints."""
import importlib
from types import ModuleType
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from django.urls import resolve, Resolver404
from rest_framework.views import APIView
from cloudfile_ext.v2.acl_http import EffectivePermission, SharedDirectories, DirectoryEntries


class RootRoutesTests(unittest.TestCase):
    def test_v2_agent2_entrypoints_never_restore_edit_session_sql(self):
        base = Path(__file__).resolve().parents[3]
        for name in ('cloudfile_ext/file_actions/service.py',
                     'cloudfile_ext/file_actions/apis.py',
                     'cloudfile_ext/file_actions/__init__.py',
                     'cloudfile_ext/v2/rust_edit.py'):
            body = (base / name).read_text()
            self.assertNotIn('cf_edit_session', body, name)
            self.assertNotIn('cf_resource', body, name)
        api = (base / 'frontend/src/cloudfile/cloudfile-api.js').read_text()
        self.assertIn('/api/v2.1/cloudfile/edit/v1/open/', api)
        self.assertNotIn('/extensions/local-edit/v1/', api)
        launcher = (base / 'frontend/src/cloudfile/agent-local-edit.js').read_text()
        self.assertIn('cloudfile-open://v2/open', launcher)
        self.assertIn("uri.hostname !== 'v2'", launcher)


    def test_compatibility_reads_resolve_to_v2_and_old_mutations_are_absent(self):
        # Only unrelated CE views and its large URL inventory are doubled.
        # Resolve the real root URLconf; real V2 request/auth contracts are
        # exercised by test_acl_http and test_effective_contract.
        modules = {}
        for name, classes in {
            'cloudfile_extensions.library_configuration': ['LibraryConfiguration'],
            'cloudfile_extensions.authorization.native_http': ['NativeRepoView'],
            'cloudfile_extensions.authorization.native_file_http': ['NativeFileView'],
        }.items():
            value = ModuleType(name)
            for cls in classes: setattr(value, cls, type(cls, (APIView,), {}))
            modules[name] = value
        native = ModuleType('seahub.urls'); native.urlpatterns = []
        modules['seahub.urls'] = native
        previous = sys.modules.pop('cloudfile_extensions.root_urls', None)
        try:
            with patch.dict(sys.modules, modules):
                urls = importlib.import_module('cloudfile_extensions.root_urls')
                prefix = '/api/v2.1/cloudfile/extensions/authorization/v1/'
                for path, view in [('effective-permission/', EffectivePermission),
                                   ('shared-directories/', SharedDirectories),
                                   ('directory-entries/', DirectoryEntries)]:
                    self.assertIs(resolve(prefix + path, urlconf=urls).func.view_class, view)
                for path in ('directory-rules/', 'directory-shares/', 'library-rules/'):
                    with self.assertRaises(Resolver404): resolve(prefix + path, urlconf=urls)
                for path in ('directory/sync/', 'extensions/identity/v1/begin/'):
                    with self.assertRaises(Resolver404):
                        resolve('/api/v2.1/cloudfile/' + path, urlconf=urls)
        finally:
            sys.modules.pop('cloudfile_extensions.root_urls', None)
            if previous is not None: sys.modules['cloudfile_extensions.root_urls'] = previous
