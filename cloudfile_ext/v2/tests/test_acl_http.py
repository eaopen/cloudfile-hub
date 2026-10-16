"""Real DRF authentication/response tests; native services are explicit test doubles."""
import time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
import jwt
from rest_framework.test import APIRequestFactory, force_authenticate

from cloudfile_ext.v2.acl_http import EffectivePermission, SharedDirectories, DirectoryRules, NativeACLCheck, DirectoryEntries
from cloudfile_ext.v2.acl_policy import Decision
from cloudfile_ext.v2.acl_runtime import ACLUnavailable

RID = '00000000-0000-4000-8000-000000000001'
KEY = 'isolated-acl-test-key-that-is-not-a-deployment-key'


class HTTPTests(TestCase):
    def request(self, view, params=None, method='get', staff=False, authenticated=True):
        factory = APIRequestFactory()
        request = getattr(factory, method)('/acl/', params or {}, format='json')
        if authenticated:
            force_authenticate(request, SimpleNamespace(username='native', is_authenticated=True, is_staff=staff))
        return view.as_view()(request)

    def test_public_rules_are_blocked_even_for_native_admin(self):
        for method in ('post', 'put', 'delete'):
            with patch('cloudfile_ext.v2.acl_http.store') as store:
                result = self.request(DirectoryRules, method=method, staff=True)
                self.assertEqual(result.status_code, 503)
                self.assertEqual(result.data['code'], 'ACL_PUBLICATION_BLOCKED')
                store.assert_not_called()
                self.assertEqual(self.request(DirectoryRules, method=method).status_code, 403)

    def test_effective_is_bound_to_authenticated_user(self):
        with patch('cloudfile_ext.v2.acl_http.Authority') as authority:
            authority.return_value.effective.return_value = Decision('rw', '/shared', True)
            result = self.request(EffectivePermission, dict(repo_id=RID, path='/shared'))
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.data['qualified_root'], '/shared')
            authority.assert_called_with('native')
            self.assertEqual(self.request(EffectivePermission, dict(repo_id=RID,path='/shared',username='owner')).status_code, 400)
            self.assertEqual(result['Cache-Control'], 'no-store')

    def test_subject_or_sql_outage_is_not_native_fallback(self):
        with patch('cloudfile_ext.v2.acl_http.Authority', side_effect=ACLUnavailable()):
            self.assertEqual(self.request(EffectivePermission, dict(repo_id=RID,path='/shared')).status_code,503)
            self.assertEqual(self.request(SharedDirectories).status_code,503)

    def test_directory_entries_require_authentication_and_preserve_root(self):
        self.assertIn(self.request(DirectoryEntries, authenticated=False).status_code,(401,403))
        with patch('cloudfile_ext.v2.acl_http.Authority') as authority:
            authority.return_value.entries.return_value = dict(data=[],root_path='/shared',next_offset=None)
            result = self.request(DirectoryEntries, dict(repo_id=RID,path='/shared'))
            self.assertEqual(result.status_code,200)
            self.assertEqual(result.data['root_path'],'/shared')

    def native(self, claims, data=None):
        token = jwt.encode(claims,KEY,algorithm='HS256')
        request = APIRequestFactory().post('/native/', data or dict(username='native',repo_id=RID,
            checks=[dict(path='/shared/file',kind='file',action='write')]), format='json',HTTP_AUTHORIZATION='Token '+token)
        with patch('cloudfile_ext.v2.acl_http.JWT_PRIVATE_KEY',KEY):
            return NativeACLCheck.as_view()(request)

    def test_native_proof_must_be_internal_short_lived_and_current(self):
        with patch('cloudfile_ext.v2.acl_http.Authority') as authority:
            authority.return_value.effective.return_value = Decision('rw','/shared',True)
            good = dict(is_internal=True,exp=int(time.time())+60)
            self.assertEqual(self.native(good).status_code,200)
            for bad in (dict(exp=int(time.time())+60),dict(is_internal=True,exp=1),dict(is_internal='true',exp=int(time.time())+60),dict(is_internal=True,exp=int(time.time())+3600)):
                self.assertEqual(self.native(bad).status_code,403)
            authority.return_value.effective.return_value = Decision('none','/shared',True)
            self.assertEqual(self.native(good).status_code,403)

    def test_native_missing_subject_adapter_and_unknown_checks_fail_closed(self):
        with patch('cloudfile_ext.v2.acl_http.Authority',side_effect=ACLUnavailable()):
            self.assertEqual(self.native(dict(is_internal=True,exp=int(time.time())+60)).status_code,503)
        with patch('cloudfile_ext.v2.acl_http.Authority'):
            result=self.native(dict(is_internal=True,exp=int(time.time())+60),dict(username='native',repo_id=RID,checks=[]))
            self.assertEqual(result.status_code,400)


class NativeFileAccessTests(TestCase):
    def test_directory_share_bypasses_only_the_whole_library_eligibility_gate(self):
        from seahub.api2.endpoints.internal_api import InternalCheckFileOperationAccess
        request=APIRequestFactory().post('/check-access/',dict(path='/shared/proof.txt',op='download'),format='json')
        force_authenticate(request,SimpleNamespace(username='native',is_authenticated=True))
        with patch('seahub.api2.endpoints.internal_api.is_valid_internal_jwt',return_value=True), \
                patch('seahub.api2.endpoints.internal_api.get_file_type_and_ext',return_value=('Text','txt')), \
                patch('seahub.api2.endpoints.internal_api.seafile_api') as api, \
                patch('seahub.api2.endpoints.internal_api.send_file_access_msg'), \
                patch('cloudfile_ext.v2.acl_runtime.protected',return_value=True), \
                patch('cloudfile_ext.v2.acl_runtime.Authority') as authority:
            api.get_file_id_by_path.return_value='f'*40
            api.check_permission_by_path.return_value=None
            authority.return_value.effective.return_value=Decision('r','/shared',True)
            result=InternalCheckFileOperationAccess.as_view()(request,repo_id=RID)
            self.assertEqual(result.status_code,200)
            self.assertEqual(result.data,{'user':'native'})
            api.check_permission_by_path.assert_not_called()
            authority.return_value.effective.assert_called_once_with(RID,'/shared/proof.txt','file')

    def test_directory_deny_is_not_ignored_for_preview_filetypes(self):
        from seahub.api2.endpoints.internal_api import InternalCheckFileOperationAccess
        request=APIRequestFactory().post('/check-access/',dict(path='/shared/proof.pdf',op='download'),format='json')
        force_authenticate(request,SimpleNamespace(username='native',is_authenticated=True))
        with patch('seahub.api2.endpoints.internal_api.is_valid_internal_jwt',return_value=True), \
                patch('seahub.api2.endpoints.internal_api.get_file_type_and_ext',return_value=('PDF','pdf')), \
                patch('seahub.api2.endpoints.internal_api.FILE_TYPE_FOR_NEW_FILE_LINK',('PDF',)), \
                patch('seahub.api2.endpoints.internal_api.seafile_api') as api, \
                patch('cloudfile_ext.v2.acl_runtime.protected',return_value=True), \
                patch('cloudfile_ext.v2.acl_runtime.Authority') as authority:
            api.get_file_id_by_path.return_value='f'*40
            authority.return_value.effective.return_value=Decision('none','/shared',True)
            result=InternalCheckFileOperationAccess.as_view()(request,repo_id=RID)
            self.assertEqual(result.status_code,403)
