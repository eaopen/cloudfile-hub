"""Current root routing must never load retired schema-dependent endpoints."""
import importlib
from types import ModuleType
import sys
import unittest
from unittest.mock import patch

from django.urls import resolve, Resolver404
from rest_framework.views import APIView
from cloudfile_ext.v2.acl_http import EffectivePermission, SharedDirectories, DirectoryEntries


class RootRoutesTests(unittest.TestCase):
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
