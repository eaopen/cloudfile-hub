"""Fast dependency-free tests for standalone and enterprise selection."""
from types import SimpleNamespace
import unittest

from cloudfile_ext.v2.subject_adapter import InvalidSubjectAdapter, selected_adapter


class SubjectAdapterPureTests(unittest.TestCase):
    def test_ce_standalone_never_requires_an_external_directory(self):
        self.assertIsNone(selected_adapter(SimpleNamespace()))
        self.assertIsNone(selected_adapter(SimpleNamespace(CF_DIRECTORY_URL='')))

    def test_existing_etech_url_uses_the_same_directory_callback(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test')),
            ('etech', 'cloudfile_ext.v2.etech_directory.ensure_subject'))

    def test_custom_enterprise_directory_may_have_no_etech_url(self):
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

    def test_half_configured_provider_never_downgrades_to_ce(self):
        for config in (
                SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test',
                                CF_ACL_PROVIDER='custom'),
                SimpleNamespace(CF_ACL_SUBJECT_ENSURE='custom.directory.ensure'),
                SimpleNamespace(CF_ACL_PROVIDER='native-local',
                                CF_ACL_SUBJECT_ENSURE='custom.directory.ensure'),
                SimpleNamespace(CF_ACL_PROVIDER='custom', CF_ACL_SUBJECT_ENSURE=''),
                SimpleNamespace(CF_ACL_PROVIDER='', CF_ACL_SUBJECT_ENSURE='custom.ensure')):
            with self.subTest(config=config), self.assertRaises(InvalidSubjectAdapter):
                selected_adapter(config)


if __name__ == '__main__':
    unittest.main()
