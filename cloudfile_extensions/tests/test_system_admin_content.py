"""Native and transactional content qualification share the Server role vectors."""
import builtins
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cloudfile_extensions.authorization.global_admin import is_system_library_admin
from cloudfile_extensions.authorization.management import LibraryOwnerManagement
from cloudfile_extensions.authorization.read import ContentReadAuthority, LibraryWideManagementAuthority


CASES = json.loads((Path(os.environ.get('CF_TEST_DOCKER_ROOT',
    Path(__file__).resolve().parents[3] / 'cloudfile-docker')) /
    'docs/system-admin-content-cases.json').read_text())['cases']


class SystemAdministratorContentTests(unittest.TestCase):
    def test_shared_roles_native_and_transactional(self):
        class MissingRole(Exception):
            pass

        username = 'admin@example.com'
        native = ModuleType('seaserv')
        native.ccnet_api = Mock()
        models = ModuleType('seahub.role_permissions.models')
        models.AdminRole = SimpleNamespace(DoesNotExist=MissingRole, objects=Mock())
        roles = ModuleType('seahub.role_permissions.utils')
        constants = ModuleType('seahub.constants')
        constants.SYSTEM_ADMIN = 'system_admin'
        real_import = builtins.__import__

        def isolated_import(name, *args, **kwargs):
            # The original regression loaded User -> config_parser -> yaml.
            if name in ('seahub.base.accounts', 'seahub.config_parser', 'yaml'):
                raise AssertionError('Unrelated runtime dependency: ' + name)
            return real_import(name, *args, **kwargs)

        for case in CASES:
            with self.subTest(case=case['id']):
                role = case.get('role')
                assigned = case.get('assigned', True)
                overrides = case.get('overrides', {})

                def permissions(value):
                    if not isinstance(overrides, dict):
                        return {'can_manage_library': False}
                    return overrides.get(value, {'can_manage_library': value in (
                        'system_admin', 'daily_admin', 'default_admin')})

                roles.get_enabled_admin_role_permissions_by_role = permissions
                native.ccnet_api.get_emailuser.return_value = SimpleNamespace(
                    email=username, is_active=int(case['active']), is_staff=int(case['staff']))
                models.AdminRole.objects.get_admin_role.side_effect = None if assigned else MissingRole()
                models.AdminRole.objects.get_admin_role.return_value = SimpleNamespace(role=role)

                class Cursor:
                    rows = ()

                    def execute(self, query, params):
                        self.rows = (('InnoDB',),) if 'information_schema' in query else (
                            ((role,),) if assigned else ())

                    def fetchall(self):
                        return self.rows

                modules = {'seaserv': native, 'seahub.role_permissions.models': models,
                    'seahub.role_permissions.utils': roles, 'seahub.constants': constants}
                with patch.dict(sys.modules, modules), patch('builtins.__import__', isolated_import):
                    self.assertIs(is_system_library_admin(username), case['expected'])
                    authority = object.__new__(ContentReadAuthority)
                    authority.state = SimpleNamespace(identity_schema='hub')
                    if role is None and assigned:
                        # Malformed role storage is unavailable, never an implicit grant.
                        from cloudfile_extensions.common.errors import ContractError
                        with self.assertRaises(ContractError):
                            authority._global_library_admin(Cursor(), username)
                    else:
                        actual = (case['active'] and case['staff'] and
                            authority._global_library_admin(Cursor(), username))
                        self.assertIs(actual, case['expected'])
                    # Daily administrators retain their background management capability.
                    if role == 'daily_admin':
                        for kind in (LibraryOwnerManagement, LibraryWideManagementAuthority):
                            manager = object.__new__(kind)
                            manager.state = authority.state
                            self.assertTrue(manager._global_library_admin(Cursor(), username))

    def test_native_role_storage_failure_is_not_a_missing_role(self):
        native = ModuleType('seaserv')
        native.ccnet_api = Mock()
        native.ccnet_api.get_emailuser.return_value = SimpleNamespace(
            email='admin@example.com', is_active=1, is_staff=1)
        models = ModuleType('seahub.role_permissions.models')
        models.AdminRole = SimpleNamespace(DoesNotExist=type('MissingRole', (Exception,), {}), objects=Mock())
        models.AdminRole.objects.get_admin_role.side_effect = RuntimeError('storage unavailable')
        permissions = ModuleType('seahub.role_permissions.utils')
        with patch.dict(sys.modules, {'seaserv': native, 'seahub.role_permissions.models': models,
                                      'seahub.role_permissions.utils': permissions}):
            permissions.get_enabled_admin_role_permissions_by_role = Mock()
            with self.assertRaisesRegex(RuntimeError, 'storage unavailable'):
                is_system_library_admin('admin@example.com')
            permissions.get_enabled_admin_role_permissions_by_role.assert_not_called()
