"""Fast dependency-free tests for standalone and enterprise selection."""
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
import importlib
import time
import unittest

from cloudfile_ext.v2.subject_adapter import (InvalidSubjectAdapter, selected_adapter,
    native_admin_identity, reserved_identity_conflict, provider_name,
    _namespace_from_entities)
from cloudfile_ext.v2.errors import IdentityUnavailable


class SubjectAdapterPureTests(unittest.TestCase):
    def test_ce_standalone_never_requires_an_external_directory(self):
        self.assertIsNone(selected_adapter(SimpleNamespace()))
        self.assertIsNone(selected_adapter(SimpleNamespace(CF_DIRECTORY_URL='')))

    def test_existing_external_url_uses_the_same_directory_callback(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test')),
            ('external', None))

    def test_preferred_provider_setting_names_the_builtin_namespace(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_DIRECTORY_PROVIDER='acme')),
            ('acme', None))

    def test_legacy_provider_setting_remains_supported(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_ACL_PROVIDER='legacy')),
            ('legacy', None))

    def test_preferred_provider_wins_when_both_are_set(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_DIRECTORY_PROVIDER='acme', CF_ACL_PROVIDER='legacy')),
            ('acme', None))

    def test_explicit_legacy_ensure_must_not_sync_during_acl_reads(self):
        self.assertEqual(selected_adapter(SimpleNamespace(
            CF_DIRECTORY_URL='https://directory.example.test',
            CF_ACL_PROVIDER='external',
            CF_ACL_SUBJECT_ENSURE='cloudfile_ext.v2.directory_adapter.ensure_subject')),
            ('external', None))

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

    def test_trusted_directory_provider_precedence_and_generic_fallback(self):
        config = SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test',
                                 CF_DIRECTORY_KEY_ID='key', CF_DIRECTORY_SECRET='x' * 32)
        with patch('cloudfile_ext.v2.subject_adapter._trusted_directory_namespace',
                   return_value='etech') as loader:
            self.assertEqual(provider_name(config), 'etech')
            self.assertEqual(selected_adapter(config), ('etech', None))
            self.assertEqual(loader.call_count, 2)
        with patch('cloudfile_ext.v2.subject_adapter._trusted_directory_namespace',
                   return_value='etech') as loader:
            explicit = SimpleNamespace(**vars(config), CF_DIRECTORY_PROVIDER='manual')
            self.assertEqual(selected_adapter(explicit), ('manual', None))
            loader.assert_not_called()
        with patch('cloudfile_ext.v2.subject_adapter._trusted_directory_namespace',
                   return_value=None):
            self.assertEqual(selected_adapter(config), ('external', None))

    def test_declared_provider_requires_fresh_verified_entities_snapshot(self):
        def snapshot(**extra):
            data = dict(contract_version='2.0', view='entities',
                        generated_at=datetime.now(timezone.utc).isoformat(),
                        groups=[dict(subject_type='org', namespace='directory',
                                     external_id='1', name='Engineering')])
            data.update(extra)
            return data

        self.assertEqual(_namespace_from_entities(snapshot(provider='etech')), 'etech')
        self.assertIsNone(_namespace_from_entities(snapshot()))
        for value in ('', ' etech', 'etech ', 'native-local', 'x' * 33):
            with self.subTest(value=value), self.assertRaises(InvalidSubjectAdapter):
                _namespace_from_entities(snapshot(provider=value))
        for facts in (
            snapshot(contract_version='1.0', provider='etech'),
            snapshot(provider='etech', generated_at=(
                datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()),
            snapshot(provider='etech', groups=[dict(subject_type='bad')]),
        ):
            with self.subTest(facts=facts), self.assertRaises(IdentityUnavailable):
                _namespace_from_entities(facts)

    def test_directory_namespace_cold_fetch_is_one_shot_and_stable(self):
        module = importlib.import_module('cloudfile_ext.v2.subject_adapter')
        module._NAMESPACE_RESOLVED.clear()
        module._NAMESPACE_RETRY_AFTER.clear()
        self.addCleanup(module._NAMESPACE_RESOLVED.clear)
        self.addCleanup(module._NAMESPACE_RETRY_AFTER.clear)
        key = ('https://directory.example.test', 'kid', 'x' * 32, 'issuer', 'aud')
        facts = dict(contract_version='2.0', view='entities', provider='etech',
                     generated_at=datetime.now(timezone.utc).isoformat(), groups=[])

        def fetch():
            time.sleep(0.02)
            return facts

        with patch.object(module, '_fetch_trusted_entities', side_effect=fetch) as call:
            with ThreadPoolExecutor(max_workers=6) as pool:
                resolved = list(pool.map(lambda _: module._trusted_directory_namespace(*key),
                                         range(6)))
            self.assertEqual(resolved, ['etech'] * 6)
            call.assert_called_once()
            self.assertEqual(module._trusted_directory_namespace(*key), 'etech')
            call.assert_called_once()

    def test_directory_namespace_failures_have_short_retry_cooldown(self):
        module = importlib.import_module('cloudfile_ext.v2.subject_adapter')
        module._NAMESPACE_RESOLVED.clear()
        module._NAMESPACE_RETRY_AFTER.clear()
        self.addCleanup(module._NAMESPACE_RESOLVED.clear)
        self.addCleanup(module._NAMESPACE_RETRY_AFTER.clear)
        key = ('https://directory-down.example.test', 'kid', 'x' * 32, 'issuer', 'aud')
        facts = dict(contract_version='2.0', view='entities', provider='etech',
                     generated_at=datetime.now(timezone.utc).isoformat(), groups=[])
        with patch.object(module, '_fetch_trusted_entities',
                          side_effect=[IdentityUnavailable('down'), facts]) as call, \
             patch.object(module.time, 'monotonic', side_effect=[100.0, 100.0, 100.0, 131.0, 131.0]):
            with self.assertRaises(IdentityUnavailable):
                module._trusted_directory_namespace(*key)
            with self.assertRaises(IdentityUnavailable):
                module._trusted_directory_namespace(*key)
            call.assert_called_once()
            self.assertEqual(module._trusted_directory_namespace(*key), 'etech')
            self.assertEqual(call.call_count, 2)

    def test_old_directory_without_namespace_uses_stable_generic_fallback(self):
        module = importlib.import_module('cloudfile_ext.v2.subject_adapter')
        module._NAMESPACE_RESOLVED.clear()
        module._NAMESPACE_RETRY_AFTER.clear()
        self.addCleanup(module._NAMESPACE_RESOLVED.clear)
        self.addCleanup(module._NAMESPACE_RETRY_AFTER.clear)
        key = ('https://legacy-directory.example.test', 'kid', 'x' * 32, 'issuer', 'aud')
        old = dict(contract_version='2.0', view='entities',
                   generated_at=datetime.now(timezone.utc).isoformat(), groups=[])
        with patch.object(module, '_fetch_trusted_entities', return_value=old) as call:
            self.assertIsNone(module._trusted_directory_namespace(*key))
            self.assertIsNone(module._trusted_directory_namespace(*key))
            call.assert_called_once()  # Upgrade EAP before Hub; restart Hub to re-resolve.

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
            ('acme', None))

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
