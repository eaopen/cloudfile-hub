"""The desired-share HTTP handler executes its plan and reports native writes."""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from django.conf import settings
if not settings.configured:
    settings.configure(SECRET_KEY='fixture', DEFAULT_CHARSET='utf-8', INSTALLED_APPS=[])
import django
django.setup()
from rest_framework.response import Response


class Cursor:
    def __init__(self):
        self.query = ''
        self.statements = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, query, arguments):
        self.query = query
        self.statements.append((query, arguments))

    def fetchone(self):
        if 'GET_LOCK' in self.query:
            return (1,)
        if 'SELECT revision' in self.query:
            return None
        return None


class LibrarySharesHttpTest(unittest.TestCase):
    def test_valid_desired_state_applies_planned_share(self):
        native = Mock()
        native.get_repo_owner.return_value = 'owner@example.com'
        native.get_org_repo_owner.return_value = None
        native.get_group_shared_repo_by_path.return_value = None
        base = type('ManagementBase', (), {'_authorize': lambda self, request, repo_id: None})
        modules = {}
        for name, attrs in {
            'seaserv': {'seafile_api': native},
            'seahub.api2.endpoints.admin.library_administrator': {'AdminLibraryAdministrator': base},
            'seahub.api2.utils': {'api_error': lambda code, message: Response({'error_msg': message}, status=code)},
        }.items():
            module = ModuleType(name)
            module.__dict__.update(attrs)
            modules[name] = module
        path = Path(__file__).resolve().parents[1] / 'library_shares.py'
        spec = importlib.util.spec_from_file_location('cloudfile_extensions.library_shares', path)
        module = importlib.util.module_from_spec(spec)
        cursor = Cursor()
        connection = Mock()
        connection.cursor.return_value = cursor
        with patch.dict(sys.modules, modules), patch.object(settings, 'CLOUDFILE_POLICY_CONFIG',
                {'provider': 'etech'}, create=True):
            spec.loader.exec_module(module)
            with patch.object(module, '_database', return_value=connection), patch.object(
                    module, 'EventWriter') as writer_class, patch.object(
                    module, 'build_share_plan', return_value=(
                        {'add': [('dept-1', 42, 'rw')], 'update': [], 'revoke': []}, [])) as planner:
                result = module.LibrarySharesDesired().put(SimpleNamespace(GET={}, user=SimpleNamespace(
                    username='admin@example.com'), data={
                    'policy_revision': 1,
                    'shares': [{'external_group_id': 'dept-1', 'permission': 'rw'}],
                }), '11111111-1111-4111-8111-111111111111')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data['applied'], {'add': 1, 'update': 0, 'revoke': 0})
        self.assertEqual(result.data['errors'], [])
        self.assertEqual(result.data['status'], 'complete')
        self.assertTrue(result.data['complete'])
        planner.assert_called_once()
        writer_class.return_value.append.assert_called_once()
        self.assertEqual(writer_class.return_value.append.call_args.args[1]['action'], 'library.share.added')
        connection.commit.assert_called_once()
        native.set_group_repo.assert_called_once_with(
            '11111111-1111-4111-8111-111111111111', 42, 'owner@example.com', 'rw')
        self.assertEqual(sum('INSERT INTO cf_library_share_ledger' in sql for sql, _ in cursor.statements), 2)


    def test_unmapped_group_is_explicitly_partial_not_a_successful_share(self):
        native = Mock()
        native.get_repo_owner.return_value = 'owner@example.com'
        native.get_org_repo_owner.return_value = None
        base = type('ManagementBase', (), {'_authorize': lambda self, request, repo_id: None})
        modules = {}
        for name, attrs in {
            'seaserv': {'seafile_api': native},
            'seahub.api2.endpoints.admin.library_administrator': {'AdminLibraryAdministrator': base},
            'seahub.api2.utils': {'api_error': lambda code, msg: Response({'error_msg': msg}, status=code)},
        }.items():
            item = ModuleType(name)
            item.__dict__.update(attrs)
            modules[name] = item
        module_path = Path(__file__).resolve().parents[1] / 'library_shares.py'
        spec = importlib.util.spec_from_file_location('cloudfile_extensions.library_shares', module_path)
        module = importlib.util.module_from_spec(spec)
        connection = Mock()
        connection.cursor.return_value = Cursor()
        with patch.dict(sys.modules, modules), patch.object(settings, 'CLOUDFILE_POLICY_CONFIG',
                {'provider': 'etech'}, create=True):
            spec.loader.exec_module(module)
            with patch.object(module, '_database', return_value=connection), patch.object(
                    module, 'build_share_plan', return_value=(
                        {'add': [], 'update': [], 'revoke': []},
                        ['missing: group mapping is missing or ambiguous'])):
                result = module.LibrarySharesDesired().put(SimpleNamespace(GET={},
                    user=SimpleNamespace(username='admin@example.com'),
                    data={'policy_revision': 2, 'shares': [
                        {'external_group_id': 'missing', 'permission': 'r'}]}),
                    '11111111-1111-4111-8111-111111111111')
        self.assertEqual(result.status_code, 200)  # compatible receipt semantics
        self.assertFalse(result.data['complete'])
        self.assertEqual(result.data['status'], 'partial')
        self.assertEqual(result.data['applied'], {'add': 0, 'update': 0, 'revoke': 0})
        self.assertEqual(result.data['planned']['add'], 1)
        self.assertEqual(len(result.data['errors']), 1)
        native.set_group_repo.assert_not_called()

if __name__ == '__main__':
    unittest.main()
