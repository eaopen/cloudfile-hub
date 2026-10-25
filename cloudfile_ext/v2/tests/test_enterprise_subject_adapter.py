"""Standalone and enterprise subject selection use configuration, not UID shape."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_ext.v2.acl_runtime import ACLUnavailable, current_principal, subject_adapter

USER = 'employee@auth.local'


class SubjectAdapterSelectionTests(TestCase):
    def test_standalone_has_no_external_subject_dependency(self):
        self.assertIsNone(subject_adapter(SimpleNamespace()))
        self.assertIsNone(subject_adapter(SimpleNamespace(CF_DIRECTORY_URL='')))

    def test_existing_directory_url_keeps_external_defaults(self):
        self.assertEqual(
            subject_adapter(SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test')),
            ('external', 'cloudfile_ext.v2.directory_adapter.ensure_subject'))

    def test_explicit_custom_provider_supports_its_own_directory_contract(self):
        self.assertEqual(subject_adapter(SimpleNamespace(
            CF_ACL_PROVIDER='corp', CF_ACL_SUBJECT_ENSURE='package.directory.refresh')),
            ('corp', 'package.directory.refresh'))

    def test_half_configured_external_provider_never_downgrades_to_ce(self):
        for config in (
                SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test', CF_ACL_PROVIDER='corp'),
                SimpleNamespace(CF_ACL_SUBJECT_ENSURE='package.directory.refresh'),
                SimpleNamespace(CF_ACL_PROVIDER='native-local',
                                CF_ACL_SUBJECT_ENSURE='package.directory.refresh'),
                SimpleNamespace(CF_ACL_PROVIDER='corp', CF_ACL_SUBJECT_ENSURE='')):
            with self.subTest(config=config), self.assertRaises(ACLUnavailable):
                subject_adapter(config)


class CurrentPrincipalSelectionTests(TestCase):
    def principal(self, uid, config, *, is_active=True, groups=(), username=USER):
        native = SimpleNamespace(email=username, is_active=is_active)
        owner = Mock()
        owner.get_profile_by_user.return_value = (
            SimpleNamespace(login_id=uid) if uid is not None else None)
        loader = Mock()
        cursor = Mock()
        cursor.fetchall.return_value = list(groups)
        manager = Mock()
        manager.__enter__ = Mock(return_value=cursor)
        manager.__exit__ = Mock(return_value=False)
        with patch('seaserv.ccnet_api.get_emailuser', return_value=native), \
             patch('seahub.profile.models.Profile.objects', owner), \
             patch('cloudfile_ext.v2.acl_runtime.settings', config), \
             patch('cloudfile_ext.v2.acl_runtime.import_string', return_value=loader) as imported, \
             patch('seahub.utils.db_api.SeafileDB', return_value=SimpleNamespace(db_name='seafile_db')), \
             patch('seahub.utils.ccnet_db.get_ccnet_db_name', return_value='accounts_db'), \
             patch('cloudfile_ext.v2.acl_runtime.identifier', side_effect=lambda value: value), \
             patch('cloudfile_ext.v2.acl_runtime.connection.cursor', return_value=manager) as connection:
            if not is_active:
                with self.assertRaises(PermissionError):
                    current_principal(username)
                return None, imported, loader, connection
            result = current_principal(username)
            return result, imported, loader, connection

    def test_standalone_numeric_uid_does_not_contact_external(self):
        result, imported, loader, connection = self.principal(
            '10280993', SimpleNamespace(CF_DIRECTORY_URL=''))
        self.assertEqual((result.provider, result.uid), ('native-local', USER))
        imported.assert_not_called()
        loader.assert_not_called()
        connection.assert_not_called()

    def test_existing_directory_adapter_is_selected_for_numeric_uid(self):
        result, imported, loader, connection = self.principal(
            '10280993', SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test'),
            groups=[('org', 'directory', 'dept-1')])
        self.assertEqual((result.provider, result.uid), ('external', '10280993'))
        self.assertIn(('org', 'directory', 'dept-1'), result.groups)
        imported.assert_called_once_with('cloudfile_ext.v2.directory_adapter.ensure_subject')
        loader.assert_called_once_with('10280993', USER)
        connection.assert_called_once()

    def test_enterprise_alphanumeric_uid_is_not_treated_as_native(self):
        config = SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test')
        result, imported, loader, connection = self.principal('employee-A', config)
        self.assertEqual((result.provider, result.uid), ('external', 'employee-A'))
        loader.assert_called_once_with('employee-A', USER)
        connection.assert_called_once()

    def test_explicit_custom_provider_works_without_directory_adapter_url(self):
        config = SimpleNamespace(CF_ACL_PROVIDER='corp',
                                 CF_ACL_SUBJECT_ENSURE='package.directory.refresh')
        result, imported, loader, connection = self.principal(
            'A-38', config, groups=[('role', 'business', 'engineer')])
        self.assertEqual((result.provider, result.uid), ('corp', 'A-38'))
        self.assertIn(('role', 'business', 'engineer'), result.groups)
        imported.assert_called_once_with('package.directory.refresh')
        loader.assert_called_once_with('A-38', USER)
        connection.assert_called_once()

    def test_external_business_admin_uses_trusted_directory_not_native(self):
        config = SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test')
        result, imported, loader, connection = self.principal(
            '9', config, username='admin@auth.local')
        self.assertEqual((result.provider, result.uid), ('external', '9'))
        loader.assert_called_once_with('9', 'admin@auth.local')
        connection.assert_called_once()

    def test_builtin_system_identity_keeps_native_admin_path(self):
        result, imported, loader, connection = self.principal(
            'cfadmin', SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test'),
            username='cfadmin@auth.local')
        self.assertEqual(result.provider, 'native-local')
        imported.assert_not_called()
        connection.assert_not_called()

    def test_inactive_account_never_reaches_enterprise_adapter(self):
        _, imported, loader, connection = self.principal(
            '123', SimpleNamespace(CF_DIRECTORY_URL='https://directory.example.test'),
            is_active=False)
        imported.assert_not_called()
        loader.assert_not_called()
        connection.assert_not_called()
