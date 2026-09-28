"""CloudFile role defaults and the two library-management tiers."""
import importlib.util
import ast
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import patch
from unittest.mock import Mock

from django.conf import settings

if not settings.configured:
    settings.configure(
        SECRET_KEY='fixture',
        DEFAULT_CHARSET='utf-8',
        ALLOWED_HOSTS=['testserver'],
        REST_FRAMEWORK={'UNAUTHENTICATED_USER': None},
        INSTALLED_APPS=[],
    )

from cloudfile_extensions.authorization.management import DirectoryManagement, LibraryOwnerManagement
from cloudfile_extensions.authorization.read import ContentReadAuthority, LibraryWideManagementAuthority
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, force_authenticate


class RolePermissionTests(unittest.TestCase):
    def test_rejected_actor_cannot_reuse_previous_management_flags(self):
        authority = object.__new__(LibraryOwnerManagement)
        authority.actor = 'trusted'
        authority.is_owner = True
        authority.is_library_admin = True
        authority.is_global_library_admin = True
        self.assertFalse(authority.authorize(None, 'other', {}))
        self.assertFalse(authority.can_manage_library())

    def test_system_scope_manages_unshared_library_but_cannot_read_its_files(self):
        actor = 'system-user-id'
        username = 'admin@example.com'
        reference = dict(repo_id='repo', path='/', kind='dir')

        class Cursor:
            rows = ()

            def execute(self, query, params):
                if 'email,is_active,is_staff' in query:
                    self.rows = ((username, 1, 1),)
                elif 'user,login_id' in query:
                    self.rows = ((username, actor),)
                elif 'information_schema' in query:
                    self.rows = (('InnoDB',),)
                elif 'SELECT repo_id FROM Repo ' in query:
                    self.rows = (('repo',),)
                elif 'SELECT status FROM RepoInfo' in query:
                    self.rows = ((0,),)
                elif 'SELECT repo_id FROM VirtualRepo' in query:
                    self.rows = ()
                elif 'SELECT owner_id FROM RepoOwner' in query:
                    self.rows = (('owner@example.com',),)
                else:
                    raise AssertionError(query)

            def fetchall(self):
                return self.rows

        def authority(kind):
            value = object.__new__(kind)
            value.actor = actor
            value.preparation = SimpleNamespace(contexts=SimpleNamespace(
                current=lambda _: dict(context_epoch=1, subject={}), allowlist=frozenset()))
            value.state = SimpleNamespace(username=lambda _: username, accounts='EmailUser',
                                          profiles='Profiles', native_schema='ccnet_db',
                                          identity_schema='seahub_db', provider='fixture')
            value.is_owner = value.is_library_admin = value.is_global_library_admin = False
            value.core = SimpleNamespace(evaluate=lambda *args, **kwargs: dict(
                visible=False, read=False, write=False))
            value.rules = SimpleNamespace(candidates=lambda *args, **kwargs: [])
            value._barriers = lambda repo: None
            value._global_library_admin = lambda cursor, user: True
            value.qualification = lambda *args: None
            return value

        self.assertTrue(authority(DirectoryManagement).authorize(Cursor(), actor, reference))
        content = authority(ContentReadAuthority)
        content._management_diagnostic = False
        self.assertFalse(content.authorize(Cursor(), actor, reference))

    def test_admin_role_api_exposes_default_system_role_and_restricts_assignment(self):
        class RoleStore:
            rows = {}

            def get_admin_role(self, email):
                if email not in self.rows:
                    raise MissingRole()
                return SimpleNamespace(role=self.rows[email])

            def add_admin_role(self, email, role):
                self.rows[email] = role

            def update_admin_role(self, email, role):
                self.rows[email] = role

        class MissingRole(Exception):
            pass

        class Role:
            DoesNotExist = MissingRole
            objects = RoleStore()

        class Account:
            DoesNotExist = type('MissingAccount', (Exception,), {})
            objects = Mock()

        Account.objects.get.return_value = SimpleNamespace(is_staff=True)

        class Enabled:
            def has_permission(self, request, view):
                return True

        modules = {}
        for name, fields in {
            'seahub.api2.authentication': dict(TokenAuthentication=SessionAuthentication),
            'seahub.api2.throttling': dict(UserRateThrottle=lambda: Mock(allow_request=lambda *a: True)),
            'seahub.api2.permissions': dict(HasRolePermissions=Enabled),
            'seahub.api2.utils': dict(api_error=lambda code, message: Response({'error_msg': message}, status=code)),
            'seahub.base.accounts': dict(User=Account),
            'seahub.role_permissions.utils': dict(get_available_admin_roles=lambda: [
                'system_admin', 'default_admin', 'daily_admin', 'audit_admin']),
            'seahub.role_permissions.models': dict(AdminRole=Role),
            'seahub.constants': dict(DEFAULT_ADMIN='default_admin', SYSTEM_ADMIN='system_admin'),
        }.items():
            module = ModuleType(name)
            module.__dict__.update(fields)
            modules[name] = module
        source = Path(__file__).resolve().parents[2] / 'seahub/api2/endpoints/admin/admin_role.py'
        spec = importlib.util.spec_from_file_location('cloudfile_admin_role_fixture', source)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(module)
        view = module.AdminAdminRole.as_view()
        factory = APIRequestFactory()
        actor = Mock(is_staff=True, is_active=True, is_authenticated=True, admin_role='system_admin',
                     username='root@example.com')
        actor.admin_permissions.can_manage_user.return_value = True
        request = factory.get('/admin-role/?email=target@example.com')
        force_authenticate(request, actor)
        self.assertEqual(view(request).data['role'], 'system_admin')
        request = factory.post('/admin-role/', {'email': 'target@example.com', 'role': 'daily_admin'})
        force_authenticate(request, actor)
        self.assertEqual(view(request).status_code, 200)
        self.assertEqual(Role.objects.rows['target@example.com'], 'daily_admin')
        actor.admin_role = 'daily_admin'
        request = factory.put('/admin-role/', {'email': 'target@example.com', 'role': 'system_admin'})
        force_authenticate(request, actor)
        self.assertEqual(view(request).status_code, 403)
        self.assertEqual(Role.objects.rows['target@example.com'], 'daily_admin')

    def test_nonstaff_or_inactive_account_cannot_inherit_system_role(self):
        source = Path(__file__).resolve().parents[2] / 'seahub/base/accounts.py'
        tree = ast.parse(source.read_text())
        admin_class = next(node for node in tree.body
                           if isinstance(node, ast.ClassDef) and node.name == 'AdminPermissions')
        namespace = {'get_enabled_admin_role_permissions_by_role': lambda role: {'can_manage_library': True}}
        exec(compile(ast.Module(body=[admin_class], type_ignores=[]), str(source), 'exec'), namespace)
        permissions = namespace['AdminPermissions'](SimpleNamespace(
            is_staff=False, is_active=True, admin_role='system_admin'))
        self.assertFalse(permissions.can_manage_library())
        permissions.user.is_staff = True
        permissions.user.is_active = False
        self.assertFalse(permissions.can_manage_library())
        permissions.user.is_active = True
        self.assertTrue(permissions.can_manage_library())

    def test_system_admin_has_all_management_permissions_and_user_roles_remain_separate(self):
        constants = ModuleType('seahub.constants')
        constants.DEFAULT_USER = 'default'
        constants.GUEST_USER = 'guest'
        constants.DEFAULT_ADMIN = 'default_admin'
        constants.SYSTEM_ADMIN = 'system_admin'
        constants.DAILY_ADMIN = 'daily_admin'
        constants.AUDIT_ADMIN = 'audit_admin'
        source = Path(__file__).resolve().parents[2] / 'seahub/role_permissions/settings.py'
        spec = importlib.util.spec_from_file_location('cloudfile_role_settings_fixture', source)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'seahub.constants': constants}):
            spec.loader.exec_module(module)
        system = module.ENABLED_ADMIN_ROLE_PERMISSIONS['system_admin']
        self.assertTrue(all(value is True for value in system.values()))
        self.assertFalse(module.ENABLED_ADMIN_ROLE_PERMISSIONS['audit_admin']['can_manage_library'])
        self.assertFalse(module.ENABLED_ROLE_PERMISSIONS['guest']['can_add_repo'])
        self.assertTrue(module.ENABLED_ROLE_PERMISSIONS['default']['can_add_repo'])

    def test_global_management_uses_native_staff_and_explicit_role_without_content_bypass(self):
        authority = object.__new__(LibraryOwnerManagement)
        authority.state = SimpleNamespace(identity_schema='seahub_db')

        class Cursor:
            def __init__(self):
                self.assigned = ()
                self.rows = ()

            def execute(self, query, params):
                if 'information_schema' in query:
                    self.rows = (('InnoDB',),)
                elif 'role_permissions_adminrole' in query:
                    self.rows = self.assigned
                else:
                    raise AssertionError(query)

            def fetchall(self):
                return self.rows

        constants = ModuleType('seahub.constants')
        constants.SYSTEM_ADMIN = 'system_admin'
        permissions = ModuleType('seahub.role_permissions.utils')
        permissions.get_enabled_admin_role_permissions_by_role = lambda role: {
            'can_manage_library': role in ('system_admin', 'daily_admin')}
        cursor = Cursor()
        with patch.dict(sys.modules, {'seahub.constants': constants,
                                      'seahub.role_permissions.utils': permissions}):
            self.assertTrue(authority._global_library_admin(cursor, 'admin@example.com'))
            cursor.assigned = (('audit_admin',),)
            self.assertFalse(authority._global_library_admin(cursor, 'admin@example.com'))
            cursor.assigned = (('daily_admin',),)
            self.assertTrue(authority._global_library_admin(cursor, 'admin@example.com'))

        content = object.__new__(ContentReadAuthority)
        self.assertFalse(content.system_admin_qualification_override())
        manager = object.__new__(LibraryWideManagementAuthority)
        self.assertTrue(manager.system_admin_qualification_override())
