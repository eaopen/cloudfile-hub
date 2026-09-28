"""The CloudFile configuration endpoint owns technical settings and scope checks."""
import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY='fixture', DEFAULT_CHARSET='utf-8', ALLOWED_HOSTS=['testserver'],
                       REST_FRAMEWORK={'UNAUTHENTICATED_USER': None}, INSTALLED_APPS=[])
import django
django.setup()
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.views import APIView


class LibraryConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.repo = SimpleNamespace(repo_name='Original', status=0, encrypted=False, is_virtual=False)
        self.native = Mock()
        self.native.get_repo.return_value = self.repo
        self.native.get_repo_owner.return_value = 'owner@example.com'
        self.native.get_repo_history_limit.return_value = 30
        self.native.edit_repo.side_effect = self.rename
        self.native.set_repo_history_limit.side_effect = self.set_history
        self.native.set_repo_status.side_effect = self.set_status
        self.audit = Mock()

        class ManagementBase(APIView):
            authentication_classes = (SessionAuthentication,)
            permission_classes = (IsAuthenticated,)

            def _authorize(self, request, repo_id):
                return None if request.user.can_manage else Response({'error_msg': 'denied'}, status=403)

        modules = {}
        for name, fields in {
            'seaserv': dict(seafile_api=self.native),
            'seahub.admin_log.models': dict(REPO_CONFIG='repo_config'),
            'seahub.admin_log.signals': dict(admin_operation=self.audit),
            'seahub.api2.endpoints.admin.library_administrator': dict(AdminLibraryAdministrator=ManagementBase),
            'seahub.api2.utils': dict(api_error=lambda code, message: Response({'error_msg': message}, status=code)),
            'seahub.utils': dict(is_valid_dirent_name=lambda value: bool(value) and '/' not in value),
            'seahub.utils.repo': dict(normalize_repo_status_str=lambda value: 0 if value == 'normal' else 1),
        }.items():
            module = ModuleType(name)
            module.__dict__.update(fields)
            modules[name] = module
        path = Path(__file__).resolve().parents[1] / 'library_configuration.py'
        spec = importlib.util.spec_from_file_location('library_configuration_fixture', path)
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(module)
        self.view = module.LibraryConfiguration.as_view()
        self.factory = APIRequestFactory()
        self.actor = Mock(is_authenticated=True, is_staff=True, username='admin@example.com', can_manage=True)
        self.actor.admin_permissions.can_manage_library.return_value = True

    def rename(self, repo_id, name, description, actor):
        self.repo.repo_name = name
        return 0

    def set_history(self, repo_id, days):
        self.native.get_repo_history_limit.return_value = days
        return 0

    def set_status(self, repo_id, value):
        self.repo.status = value

    def request(self, method, data=None, actor=None):
        path = '/libraries/repo/configuration/'
        request = (self.factory.get(path) if method == 'get'
                   else self.factory.put(path, data, format='json'))
        force_authenticate(request, actor or self.actor)
        return self.view(request, repo_id='repo')

    def test_reads_native_configuration_and_updates_one_setting(self):
        result = self.request('get')
        self.assertEqual(result.status_code, status.HTTP_200_OK)
        self.assertEqual(result.data['history_keep_days'], 30)
        self.assertEqual(result['Cache-Control'], 'no-store')
        self.assertEqual(self.request('put', {'name': 'Renamed'}).data['name'], 'Renamed')
        self.assertEqual(self.request('put', {'history_keep_days': 7}).data['history_keep_days'], 7)
        self.assertEqual(self.request('put', {'status': 'read-only'}).data['status'], 1)
        self.assertEqual(self.audit.send.call_count, 3)

    def test_library_manager_cannot_change_system_status(self):
        manager = Mock(is_authenticated=True, is_staff=False, username='manager@example.com', can_manage=True)
        result = self.request('put', {'status': 'read-only'}, actor=manager)
        self.assertEqual(result.status_code, status.HTTP_403_FORBIDDEN)
        self.native.set_repo_status.assert_not_called()
        self.assertEqual(self.request('put', {'name': 'Allowed'}, actor=manager).status_code, 200)

    def test_rejects_partial_and_unconfirmed_mutations(self):
        self.assertEqual(self.request('put', {'name': 'x', 'status': 'normal'}).status_code, 400)
        self.assertEqual(self.request('put', {'history_keep_days': True}).status_code, 400)
        self.actor.can_manage = False
        self.assertEqual(self.request('put', {'name': 'No'}).status_code, 403)
        self.actor.can_manage = True
        self.native.set_repo_history_limit.return_value = -1
        self.native.set_repo_history_limit.side_effect = None
        with self.assertLogs('library_configuration_fixture', level='ERROR'):
            self.assertEqual(self.request('put', {'history_keep_days': 14}).status_code, 503)
