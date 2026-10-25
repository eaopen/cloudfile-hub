"""Fast dependency-free tests for standalone and enterprise selection."""
from types import SimpleNamespace
import unittest

from cloudfile_ext.v2.subject_adapter import (InvalidSubjectAdapter, selected_adapter,
    native_admin_identity, reserved_identity_conflict)


class SubjectAdapterPureTests(unittest.TestCase):
    def test_ce_standalone_never_requires_an_external_directory(self):
        self.assertIsNone(selected_adapter(SimpleNamespace()))
        self.assertIsNone(selected_adapter(SimpleNamespace(CF_DIRECTORY_URL='')))

    def test_existing_external_url_uses_the_same_directory_callback(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test')),
            ('external', 'cloudfile_ext.v2.directory_adapter.ensure_subject'))

    def test_preferred_provider_setting_names_the_builtin_namespace(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_DIRECTORY_PROVIDER='acme')),
            ('acme', 'cloudfile_ext.v2.directory_adapter.ensure_subject'))

    def test_legacy_provider_setting_remains_supported(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_ACL_PROVIDER='legacy')),
            ('legacy', 'cloudfile_ext.v2.directory_adapter.ensure_subject'))

    def test_preferred_provider_wins_when_both_are_set(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_DIRECTORY_PROVIDER='acme', CF_ACL_PROVIDER='legacy')),
            ('acme', 'cloudfile_ext.v2.directory_adapter.ensure_subject'))

    def test_custom_enterprise_directory_may_have_no_external_url(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_ACL_PROVIDER='acme', CF_ACL_SUBJECT_ENSURE='acme.directory.refresh')),
            ('acme', 'acme.directory.refresh'))

    def test_malformed_provider_configuration_fails_before_import(self):
        for provider, ensure in (
                (' corp', 'corp.directory.refresh'),
                ('corp ', 'corp.directory.refresh'),
                ('corp', ' corp.directory.refresh'),
                ('corp', 'corp.directory.refresh '),
                ('corp', 'refresh'),
                ('a' * 129, 'corp.directory.refresh')):
            with self.subTest(provider=provider, ensure=ensure), self.assertRaises(InvalidSubjectAdapter):
                selected_adapter(SimpleNamespace(
                    CF_ACL_PROVIDER=provider, CF_ACL_SUBJECT_ENSURE=ensure))

    def test_builtin_admin_bypass_requires_exact_account_and_uid(self):
        for username in ('cfadmin@auth.local',):
            self.assertTrue(native_admin_identity('cfadmin', username))
            self.assertFalse(reserved_identity_conflict('cfadmin', username))
        for uid, username in (
                ('cfadmin', 'employee@auth.local'),
                ('9', 'cfadmin@auth.local'),
                ('cfadmin', 'admin@auth.local'),
                ('cfadmin', 'cfadmin@example.com')):
            with self.subTest(uid=uid, username=username):
                self.assertFalse(native_admin_identity(uid, username))
                self.assertTrue(reserved_identity_conflict(uid, username))
        self.assertFalse(reserved_identity_conflict('9', 'admin@auth.local'))

    def test_namespace_override_keeps_builtin_adapter(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_ACL_PROVIDER='acme')),
            ('acme', 'cloudfile_ext.v2.directory_adapter.ensure_subject'))

    def test_half_configured_provider_never_downgrades_to_ce(self):
        for config in (
                SimpleNamespace(CF_ACL_SUBJECT_ENSURE='custom.directory.ensure'),
                SimpleNamespace(CF_ACL_PROVIDER='native-local',
                                CF_ACL_SUBJECT_ENSURE='custom.directory.ensure'),
                SimpleNamespace(CF_ACL_PROVIDER='custom', CF_ACL_SUBJECT_ENSURE=''),
                SimpleNamespace(CF_ACL_PROVIDER='', CF_ACL_SUBJECT_ENSURE='custom.ensure')):
            with self.subTest(config=config), self.assertRaises(InvalidSubjectAdapter):
                selected_adapter(config)


if __name__ == '__main__':
    unittest.main()
