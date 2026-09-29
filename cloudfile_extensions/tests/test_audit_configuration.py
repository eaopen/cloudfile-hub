import importlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from django.test import override_settings

from cloudfile_extensions.events.configuration import require_export_configuration


class AuditConfigurationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cloudfile_extensions.tests.test_audit_http import AuditHTTPTest
        AuditHTTPTest.setUpClass()

    def test_export_routes_are_explicit_and_reversible(self):
        from cloudfile_extensions.events import urls
        try:
            for enabled in (False, True, False):
                with override_settings(CLOUDFILE_AUDIT_EXPORT_ENABLED=enabled):
                    patterns = importlib.reload(urls).urlpatterns
                    names = {item.name for item in patterns}
                    self.assertEqual('audit-export-create' in names, enabled)
                    self.assertEqual('audit-export-result' in names, enabled)
                    self.assertIn('audit-object-access', names)
        finally:
            importlib.reload(urls)

    def test_private_directory_and_strict_flags(self):
        with tempfile.TemporaryDirectory() as root:
            flags = dict(CLOUDFILE_AUDIT_EXPORT_ENABLED=True, CLOUDFILE_AUDIT_QUERY_ENABLED=True,
                CLOUDFILE_OIDC_ENABLED=True, CLOUDFILE_AUTHORIZATION_ENABLED=True)
            settings = SimpleNamespace(**flags, CLOUDFILE_AUDIT_RESULT_ROOT=root)
            self.assertEqual(require_export_configuration(settings), root)
            for name in flags:
                for value in (False, 'true'):
                    setattr(settings, name, value)
                    with self.assertRaises(ValueError):
                        require_export_configuration(settings)
                setattr(settings, name, True)
            os.chmod(root, 0o755)
            with self.assertRaises(ValueError):
                require_export_configuration(settings)
            os.chmod(root, 0o700)
            link = Path(root) / 'alias'
            link.symlink_to(root, target_is_directory=True)
            settings.CLOUDFILE_AUDIT_RESULT_ROOT = str(link)
            with self.assertRaises(OSError):
                require_export_configuration(settings)
