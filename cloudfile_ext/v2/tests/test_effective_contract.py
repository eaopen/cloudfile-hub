"""Current effective-permission HTTP contract, with the real V2 scope resolver.

Native C RPC and sparse SQL rows are explicit doubles. These checks exercise
upload eligibility returned to the client; native byte transfer remains an
integration check against a matching Server.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from rest_framework.test import APIRequestFactory, force_authenticate

from cloudfile_ext.v2.acl_http import EffectivePermission
from cloudfile_ext.v2.acl_policy import Principal, Rule
from cloudfile_ext.v2.acl_runtime import Authority

RID = '11111111-1111-4111-8111-111111111111'
USERNAME = 'member@auth.local'
ENDPOINT = '/api/v2.1/cloudfile/authorization/v1/effective-permission/'


class EffectiveContractTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock()
        self.api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=1)
        self.api.get_repo_status.return_value = 0
        self.api.check_permission.return_value = 'r'
        self.api.check_permission_by_path.side_effect = lambda repo, path, username: (
            'rw' if path == '/writable' or path.startswith('/writable/') else 'r')
        self.rules = Mock()
        self.rules.library.return_value = (
            Rule(RID, '/writable', 'etech', 'user', 'user', 'uid', 'rw'),)
        self.principal = Principal('etech', 'uid')
        ttl = patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=0)
        ttl.start()
        self.addCleanup(ttl.stop)

    def request(self, path='/writable', *, staff=False, extra=None, kind='dir'):
        raw = APIRequestFactory().get(ENDPOINT, dict(repo_id=RID, path=path, kind=kind, **(extra or {})))
        force_authenticate(raw, SimpleNamespace(username=USERNAME,
            is_authenticated=True, is_staff=staff, is_active=True,
            admin_permissions=SimpleNamespace(can_manage_library=lambda: staff)))
        authority = Authority(USERNAME, principal=self.principal, rules=self.rules, api=self.api)
        with patch('cloudfile_ext.v2.acl_http.Authority', return_value=authority) as factory:
            result = EffectivePermission.as_view()(raw)
        self.assertEqual(result.get('Cache-Control'), 'no-store')
        return result, factory

    def test_library_read_does_not_cap_explicit_child_write(self):
        result, factory = self.request('/writable/new-folder')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data, dict(permission='rw', qualified_root='/', from_rule=True,
            read=True, write=True, visible=True, protected_publication=False))
        factory.assert_called_once_with(USERNAME)
        self.api.check_permission_by_path.assert_called_once_with(RID, '/writable/new-folder', USERNAME)

    def test_file_uses_exact_native_resource_and_shared_scope_stays_bounded(self):
        self.api.check_permission.return_value = None
        self.rules.library.return_value = (
            Rule(RID, '/writable', 'etech', 'user', 'user', 'uid', 'rw', True, True),)
        result, _ = self.request('/writable/proof.txt', kind='file')
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.data['write'])
        self.assertEqual(result.data['qualified_root'], '/writable')
        self.api.check_permission_by_path.assert_called_once_with(RID, '/writable/proof.txt', USERNAME)
        self.assertEqual(self.request('/')[0].status_code, 403)

    def test_library_root_and_sibling_read_deny_upload(self):
        for path in ('/', '/sibling'):
            with self.subTest(path=path):
                result, _ = self.request(path)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.data['permission'], 'r')
                self.assertTrue(result.data['read'])
                self.assertFalse(result.data['write'])

    def test_unqualified_user_gets_403(self):
        self.api.check_permission.return_value = None
        self.principal = Principal('etech', 'other-user')
        result, _ = self.request()
        self.assertEqual(result.status_code, 403)
        self.assertEqual(result.data, {'code': 'ACL_DENIED'})
        self.api.check_permission_by_path.assert_not_called()

    def test_management_role_does_not_supply_content_write(self):
        result, _ = self.request('/', staff=True)
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.data['write'])
        self.api.check_permission.return_value = None
        self.principal = Principal('etech', 'other-user')
        result, _ = self.request('/', staff=True)
        self.assertEqual(result.status_code, 403)

    def test_native_policy_outage_never_returns_allow(self):
        self.api.check_permission_by_path.side_effect = RuntimeError('native policy offline')
        result, _ = self.request()
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.data, {'code': 'ACL_UNAVAILABLE'})
        self.assertNotIn('write', result.data)

    def test_native_read_or_revoke_can_narrow_a_scope_grant(self):
        for permission, status in (('r', 200), (None, 403), ('invisible', 403)):
            with self.subTest(permission=permission):
                self.api.check_permission_by_path.side_effect = None
                self.api.check_permission_by_path.return_value = permission
                result, _ = self.request()
                self.assertEqual(result.status_code, status)
                self.assertFalse(result.data.get('write', False))

    def test_native_cannot_widen_scope_or_readonly_repository(self):
        self.api.check_permission_by_path.side_effect = None
        self.api.check_permission_by_path.return_value = 'rw'
        result, _ = self.request('/sibling')
        self.assertFalse(result.data['write'])
        self.api.get_repo_status.return_value = 1
        result, _ = self.request('/writable')
        self.assertFalse(result.data['write'])

    def test_native_management_marker_or_invalid_permission_is_not_rw(self):
        for permission in ('admin', 'unknown'):
            with self.subTest(permission=permission):
                self.api.check_permission_by_path.side_effect = None
                self.api.check_permission_by_path.return_value = permission
                result, _ = self.request()
                self.assertEqual(result.status_code, 503)
                self.assertNotIn('write', result.data)

    def test_sql_failure_does_not_fall_back_to_native_write(self):
        self.rules.library.side_effect = RuntimeError('SQL offline')
        result, _ = self.request()
        self.assertEqual(result.status_code, 503)
        self.api.check_permission_by_path.assert_not_called()

    def test_subject_override_is_rejected_before_policy(self):
        result, factory = self.request(extra={'username': 'owner'})
        self.assertEqual(result.status_code, 400)
        factory.assert_not_called()
        self.api.check_permission_by_path.assert_not_called()

    def test_anonymous_cannot_inspect_content_permissions(self):
        raw = APIRequestFactory().get(ENDPOINT, dict(repo_id=RID, path='/writable'))
        # Avoid the unauthenticated token backend's native database dependency.
        # DRF still executes the endpoint's real IsAuthenticated permission.
        with patch.object(EffectivePermission, 'authentication_classes', ()):
            result = EffectivePermission.as_view()(raw)
        self.assertEqual(result.status_code, 403)
        self.api.check_permission_by_path.assert_not_called()
