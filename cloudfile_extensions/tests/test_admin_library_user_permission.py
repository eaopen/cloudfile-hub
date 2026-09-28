"""Exercise the real management view with native storage/authentication fixtures."""
import importlib.util
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY='fixture', DEFAULT_CHARSET='utf-8', ALLOWED_HOSTS=['testserver'], REST_FRAMEWORK={
        'UNAUTHENTICATED_USER': None}, INSTALLED_APPS=[])
import django
django.setup()
from django.core.validators import validate_email
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, force_authenticate


class AdminLibraryUserPermissionTests(unittest.TestCase):
    def setUp(self):
        self.native = Mock()
        self.native.get_repo.return_value = object()
        self.native.get_repo_owner.return_value = 'owner@example.com'
        self.native.get_org_repo_owner.return_value = None
        self.native.check_permission.return_value = 'rw'
        self.users = Mock()
        self.users.DoesNotExist = type('MissingUser', (Exception,), {})
        self.target = SimpleNamespace(username='alice@example.com', is_active=True)
        self.users.objects.get.return_value = self.target
        self.import_user = Mock(return_value=self.target)
        self.auth_backend = Mock(return_value=SimpleNamespace(get_user_with_import=self.import_user))
        self.profile = Mock()
        self.profile.objects.get_contact_email_by_user.side_effect = lambda username: username
        self.management = Mock(return_value=False)
        self.resolve_email = Mock(side_effect=lambda email: email)
        def valid_email(email):
            try:
                validate_email(email)
                return True
            except Exception:
                return False
        modules = {}
        for name, fields in {
            'seaserv': dict(seafile_api=self.native, ccnet_api=Mock()),
            'seahub.api2.authentication': dict(TokenAuthentication=SessionAuthentication),
            'seahub.api2.throttling': dict(UserRateThrottle=lambda: Mock(allow_request=lambda *a: True)),
            'seahub.api2.utils': dict(api_error=lambda code, text: Response({'error_msg': text}, status=code)),
            'seahub.base.accounts': dict(User=self.users, AuthBackend=self.auth_backend),
            'seahub.auth.utils': dict(get_virtual_id_by_email=self.resolve_email),
            'seahub.profile.models': dict(Profile=self.profile),
            'seahub.share.utils': dict(is_repo_admin=self.management,
                share_dir_to_user=Mock(), share_dir_to_group=Mock()),
            'seahub.utils': dict(is_valid_email=valid_email, send_perm_audit_msg=Mock()),
        }.items():
            module = ModuleType(name)
            module.__dict__.update(fields)
            modules[name] = module
        path = Path(__file__).resolve().parents[2] / 'seahub/api2/endpoints/admin/library_user_permission.py'
        spec = importlib.util.spec_from_file_location('permission_view_fixture', path)
        self.module = importlib.util.module_from_spec(spec)
        self.modules = modules
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(self.module)
        self.view = self.module.AdminLibraryUserPermission.as_view()
        self.requests = APIRequestFactory()
        self.actor = Mock(is_staff=True, is_authenticated=True)
        self.actor.admin_permissions.can_manage_library.return_value = True

    def query(self, query='email=alice%40example.com', actor=True):
        request = self.requests.get('/permissions/?' + query)
        if actor:
            force_authenticate(request, self.actor)
        return self.view(request, repo_id='repo')

    def test_content_and_management_are_independent_and_target_is_explicit(self):
        result = self.query()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['permission'], 'rw')
        self.assertFalse(result.data['repo_admin'])
        self.assertFalse(result.data['is_owner'])
        self.assertFalse(result.data['directory_acl_applied'])
        self.assertEqual(result['Cache-Control'], 'no-store')
        self.native.check_permission.assert_called_once_with('repo', 'alice@example.com')
        self.management.assert_called_once_with('alice@example.com', 'repo', strict=True)
        self.management.return_value = True
        self.native.check_permission.return_value = 'r'
        self.assertTrue(self.query().data['repo_admin'])
        self.assertEqual(self.query().data['permission'], 'r')

    def test_anonymous_ordinary_or_non_library_admin_cannot_probe(self):
        self.assertIn(self.query(actor=False).status_code, (401, 403))
        self.actor.is_staff = False
        self.assertEqual(self.query().status_code, 403)
        self.actor.is_staff = True
        self.actor.admin_permissions.can_manage_library.return_value = False
        self.assertEqual(self.query().status_code, 403)
        self.native.get_repo.assert_not_called()

    def test_query_validation_missing_entities_and_inactive_user(self):
        for query in ('', 'email=bad', 'email=a%40b.com&email=c%40d.com', 'email=a%40b.com&path=/'):
            self.assertEqual(self.query(query).status_code, 400)
        self.native.get_repo.return_value = None
        self.assertEqual(self.query().status_code, 404)
        self.native.get_repo.return_value = object()
        self.users.objects.get.side_effect = self.users.DoesNotExist()
        self.assertEqual(self.query().status_code, 404)
        self.users.objects.get.side_effect = None
        self.target.is_active = False
        result = self.query()
        self.assertEqual(result.data['permission'], 'none')
        self.assertFalse(result.data['repo_admin'])
        self.native.check_permission.assert_not_called()

    def test_lookup_failure_is_503_instead_of_successful_none(self):
        self.management.side_effect = RuntimeError('storage unavailable')
        with self.assertLogs(self.module.logger, level='ERROR'):
            self.assertEqual(self.query().status_code, 503)
        self.management.side_effect = None
        self.native.check_permission.return_value = 'unknown'
        with self.assertLogs(self.module.logger, level='ERROR'):
            self.assertEqual(self.query().status_code, 503)

    def test_contact_email_resolves_to_virtual_id_without_org_rpc(self):
        self.resolve_email.side_effect = None
        self.resolve_email.return_value = 'opaque@auth.local'
        self.target.username = 'opaque@auth.local'
        del self.native.get_org_repo_owner
        result = self.query('email=admin%40example.com')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['email'], 'admin@example.com')
        self.assertEqual(result.data['permission'], 'rw')
        self.users.objects.get.assert_called_once_with(email='opaque@auth.local')
        self.native.check_permission.assert_called_once_with('repo', 'opaque@auth.local')

    def test_administrator_grant_imports_unseen_directory_user(self):
        user_grants, group_grants = Mock(), Mock()
        models = ModuleType('seahub.share.models')
        models.ExtraSharePermission = user_grants
        models.ExtraGroupsSharePermission = group_grants
        path = Path(__file__).resolve().parents[2] / 'seahub/api2/endpoints/admin/library_administrator.py'
        spec = importlib.util.spec_from_file_location('administrator_import_fixture', path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {**self.modules, 'seahub.share.models': models}):
            spec.loader.exec_module(module)
        view = module.AdminLibraryAdministrator.as_view()
        self.users.objects.get.side_effect = self.users.DoesNotExist()
        self.target.username = 'imported@auth.local'
        self.native.get_shared_repo_by_path.return_value = object()
        user_grants.objects.get_or_create.return_value = (SimpleNamespace(permission='admin'), True)

        def grant():
            request = self.requests.post('/administrator/', {'subject_type': 'user',
                'subject': 'directory-user@example.com'}, format='json')
            force_authenticate(request, self.actor)
            with patch.object(module.transaction, 'atomic', nullcontext):
                return view(request, repo_id='repo')

        result = grant()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['subject'], 'directory-user@example.com')
        self.import_user.assert_called_once_with('directory-user@example.com')
        user_grants.objects.get_or_create.assert_called_once_with(
            repo_id='repo', share_to='imported@auth.local',
            defaults={'permission': 'admin', 'auto_granted_read': False})

        user_grants.objects.get_or_create.reset_mock()
        self.import_user.side_effect = self.users.DoesNotExist()
        self.assertEqual(grant().status_code, 404)
        user_grants.objects.get_or_create.assert_not_called()

        self.import_user.side_effect = None
        self.target.is_active = False
        self.assertEqual(grant().status_code, 409)
        user_grants.objects.get_or_create.assert_not_called()

    def test_administrator_removal_preserves_native_content_shares(self):
        user_grants, group_grants = Mock(), Mock()
        models = ModuleType('seahub.share.models')
        models.ExtraSharePermission = user_grants
        models.ExtraGroupsSharePermission = group_grants
        audit = Mock()
        self.modules['seahub.utils'].send_perm_audit_msg = audit
        path = Path(__file__).resolve().parents[2] / 'seahub/api2/endpoints/admin/library_administrator.py'
        spec = importlib.util.spec_from_file_location('administrator_view_fixture', path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {**self.modules, 'seahub.share.models': models}):
            spec.loader.exec_module(module)
        view = module.AdminLibraryAdministrator.as_view()
        for kind, subject in [('user', 'alice@example.com'), ('group', '42')]:
            request = self.requests.delete('/administrator/?subject_type=' + kind + '&subject=' + subject)
            force_authenticate(request, self.actor)
            with patch.object(module.transaction, 'atomic', nullcontext):
                result = view(request, repo_id='repo')
            self.assertEqual(result.status_code, 200)
            self.assertTrue(result.data['removed'])
        user_grants.objects.delete_share_permission.assert_called_once_with('repo', 'alice@example.com')
        group_grants.objects.delete_share_permission.assert_called_once_with('repo', 42)
        self.native.remove_share.assert_not_called()
        self.native.unset_group_repo.assert_not_called()
        self.assertEqual(audit.call_count, 2)

        user_grants.objects.get_or_create.return_value = (SimpleNamespace(permission='admin'), True)
        request = self.requests.post('/administrator/', {'subject_type': 'user',
            'subject': 'alice@example.com'}, format='json')
        force_authenticate(request, self.actor)
        with patch.object(module.transaction, 'atomic', nullcontext):
            granted = view(request, repo_id='repo')
        self.assertEqual(granted.status_code, 200)
        self.assertTrue(granted.data['granted'])
        user_grants.objects.get_or_create.assert_called_once_with(
            repo_id='repo', share_to='alice@example.com',
            defaults={'permission': 'admin', 'auto_granted_read': False})
        self.native.share_repo.assert_not_called()
        self.modules['seahub.share.utils'].share_dir_to_user.assert_not_called()

        # Granting an administrator to an unshared user adds only read access.
        user_grants.objects.get_or_create.reset_mock()
        self.native.get_shared_repo_by_path.return_value = None
        self.native.check_permission.return_value = 'r'
        request = self.requests.post('/administrator/', {'subject_type': 'user',
            'subject': 'alice@example.com'}, format='json')
        force_authenticate(request, self.actor)
        with patch.object(module.transaction, 'atomic', nullcontext):
            self.assertEqual(view(request, repo_id='repo').status_code, 200)
        self.modules['seahub.share.utils'].share_dir_to_user.assert_called_once_with(
            self.native.get_repo.return_value, '/', self.native.get_repo_owner.return_value,
            self.actor.username, 'alice@example.com', 'r', org_id=None)
        self.native.get_org_id_by_repo_id.assert_not_called()
        user_grants.objects.get_or_create.assert_called_once_with(
            repo_id='repo', share_to='alice@example.com',
            defaults={'permission': 'admin', 'auto_granted_read': True})
        self.native.get_shared_repo_by_path.return_value = Mock(permission='r')

        user_grants.objects.get_or_create.reset_mock()
        self.native.get_shared_repo_by_path.side_effect = [None, SimpleNamespace(permission='r')]
        self.native.check_permission.return_value = None
        request = self.requests.post('/administrator/', {'subject_type': 'user',
            'subject': 'alice@example.com'}, format='json')
        force_authenticate(request, self.actor)
        with patch.object(module.transaction, 'atomic', nullcontext), self.assertLogs(module.logger, level='ERROR'):
            self.assertEqual(view(request, repo_id='repo').status_code, 503)
        user_grants.objects.get_or_create.assert_not_called()
        self.native.remove_share.assert_called_once_with(
            'repo', 'owner@example.com', 'alice@example.com')
        self.native.get_shared_repo_by_path.side_effect = None
        self.native.get_shared_repo_by_path.return_value = Mock(permission='r')
        self.native.check_permission.return_value = 'rw'

        group_grants.objects.get_or_create.return_value = (SimpleNamespace(permission='admin'), True)
        self.native.get_group_shared_repo_by_path.side_effect = [None, object()]
        self.native.get_org_repo_owner.return_value = None
        request = self.requests.post('/administrator/', {'subject_type': 'group',
            'subject': '42'}, format='json')
        force_authenticate(request, self.actor)
        with patch.object(module.transaction, 'atomic', nullcontext):
            self.assertEqual(view(request, repo_id='repo').status_code, 200)
        self.modules['seahub.share.utils'].share_dir_to_group.assert_called_once_with(
            self.native.get_repo.return_value, '/', self.native.get_repo_owner.return_value,
            self.actor.username, 42, 'r', org_id=None)
        group_grants.objects.get_or_create.assert_called_once_with(
            repo_id='repo', group_id=42,
            defaults={'permission': 'admin', 'auto_granted_read': True})
        self.native.get_group_shared_repo_by_path.side_effect = None

        user_grants.objects.get_admin_users_by_repo.return_value = ['alice@example.com']
        group_grants.objects.get_admin_groups_by_repo.return_value = [42]
        request = self.requests.get('/administrator/')
        force_authenticate(request, self.actor)
        listed = view(request, repo_id='repo')
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.data['administrators']), 2)
        self.assertTrue(all(row['effective'] for row in listed.data['administrators']))
        self.native.check_permission.return_value = None
        listed = view(request, repo_id='repo')
        self.assertFalse(listed.data['administrators'][0]['effective'])
        self.native.check_permission.return_value = 'rw'

        self.actor.is_staff = False
        self.management.return_value = False
        request = self.requests.post('/administrator/', {'subject_type': 'user',
            'subject': 'alice@example.com'}, format='json')
        force_authenticate(request, self.actor)
        self.assertEqual(view(request, repo_id='repo').status_code, 403)

    def test_administrator_removal_revokes_only_auto_created_read_shares(self):
        user_grants, group_grants = Mock(), Mock()
        user_grants.objects.select_for_update.return_value.filter.return_value.first.return_value = (
            SimpleNamespace(auto_granted_read=True))
        group_grants.objects.select_for_update.return_value.filter.return_value.first.return_value = (
            SimpleNamespace(auto_granted_read=True))
        models = ModuleType('seahub.share.models')
        models.ExtraSharePermission = user_grants
        models.ExtraGroupsSharePermission = group_grants
        path = Path(__file__).resolve().parents[2] / 'seahub/api2/endpoints/admin/library_administrator.py'
        spec = importlib.util.spec_from_file_location('administrator_auto_read_fixture', path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {**self.modules, 'seahub.share.models': models}):
            spec.loader.exec_module(module)
        view = module.AdminLibraryAdministrator.as_view()
        self.native.get_org_repo_owner.return_value = None
        self.native.get_shared_repo_by_path.return_value = SimpleNamespace(permission='r')
        self.native.get_group_shared_repo_by_path.return_value = SimpleNamespace(permission='r')
        for kind, subject in [('user', 'alice@example.com'), ('group', '42')]:
            request = self.requests.delete('/administrator/?subject_type=' + kind + '&subject=' + subject)
            force_authenticate(request, self.actor)
            with patch.object(module.transaction, 'atomic', nullcontext):
                self.assertEqual(view(request, repo_id='repo').status_code, 200)
        self.native.remove_share.assert_called_once_with('repo', 'owner@example.com', 'alice@example.com')
        self.native.unset_group_repo.assert_called_once_with('repo', 42, 'owner@example.com')

        self.native.remove_share.reset_mock()
        self.native.get_shared_repo_by_path.return_value = SimpleNamespace(permission='rw')
        request = self.requests.delete('/administrator/?subject_type=user&subject=alice%40example.com')
        force_authenticate(request, self.actor)
        with patch.object(module.transaction, 'atomic', nullcontext):
            self.assertEqual(view(request, repo_id='repo').status_code, 200)
        self.native.remove_share.assert_not_called()

    def test_native_management_strict_mode_propagates_storage_errors(self):
        # Load the existing native helper's actual source, without requiring a live Seahub DB.
        import ast
        source = Path(__file__).resolve().parents[2] / 'seahub/share/utils.py'
        tree = ast.parse(source.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'is_repo_admin')
        shares = Mock()
        shares.objects.get_user_permission.side_effect = RuntimeError('DB unavailable')
        native = Mock()
        native.check_permission.return_value = 'rw'
        native.get_repo_owner.return_value = 'owner@example.com'
        namespace = dict(ExtraSharePermission=shares, logger=Mock(), PERMISSION_ADMIN='admin',
                         PERMISSION_READ_WRITE='rw', seafile_api=native)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertFalse(namespace['is_repo_admin']('user', 'repo'))
        with self.assertRaises(RuntimeError):
            namespace['is_repo_admin']('user', 'repo', strict=True)

    def test_group_admin_marker_requires_live_group_share(self):
        import ast
        source = Path(__file__).resolve().parents[2] / 'seahub/share/utils.py'
        tree = ast.parse(source.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'is_repo_admin')
        users, groups, native = Mock(), Mock(), Mock()
        users.objects.get_user_permission.return_value = None
        groups.objects.get_admin_groups_by_repo.return_value = [42]
        native.check_permission.return_value = 'rw'
        native.get_repo_owner.return_value = 'owner@example.com'
        native.get_group_shared_repo_by_path.return_value = None
        namespace = dict(ExtraSharePermission=users, ExtraGroupsSharePermission=groups,
                         logger=Mock(), PERMISSION_ADMIN='admin', PERMISSION_READ_WRITE='rw',
                         seafile_api=native, is_group_admin=lambda group, user: True)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
        self.assertFalse(namespace['is_repo_admin']('manager@example.com', 'repo'))
        native.get_group_shared_repo_by_path.return_value = object()
        self.assertTrue(namespace['is_repo_admin']('manager@example.com', 'repo'))

        # The CE backend has no organization owner RPC.
        del native.get_org_repo_owner
        self.assertTrue(namespace['is_repo_admin']('manager@example.com', 'repo', strict=True))
