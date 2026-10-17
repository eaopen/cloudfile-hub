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
            force_authenticate(request, SimpleNamespace(username='native', is_authenticated=True, is_staff=staff, is_active=True))
        return view.as_view()(request)

    def test_public_mutation_remains_blocked_until_native_acl_is_enabled(self):
        for method in ('post', 'put', 'delete'):
            with patch('cloudfile_ext.v2.acl_http.store') as rules:
                result = self.request(DirectoryRules, method=method)
                self.assertEqual(result.status_code, 503)
                self.assertEqual(result.data['code'], 'ACL_NATIVE_ENFORCEMENT_REQUIRED')
                rules.assert_not_called()

    def test_directory_rules_allow_native_repo_admin_without_system_staff(self):
        with patch('cloudfile_ext.v2.acl_http.require_repo_manage') as guard, \
             patch('cloudfile_ext.v2.acl_http.store') as rules, \
             patch('cloudfile_ext.v2.acl_http.settings') as settings:
            settings.CF_ACL_PROVIDER = 'etech'
            rules.return_value.list_path.return_value = []
            result = self.request(DirectoryRules, dict(repo_id=RID, path='/folder'))
            self.assertEqual(result.status_code, 200)
            guard.assert_called_once()
            self.assertEqual(guard.call_args.args[1], RID)
            self.assertEqual(result.data['data'], [])
            guard.side_effect = PermissionError('no repo-admin rights')
            self.assertEqual(self.request(DirectoryRules, dict(repo_id=RID,path='/folder')).status_code,403)

    def test_native_repo_admin_marker_is_required_for_acl_delegation(self):
        from cloudfile_ext.v2.acl_http import require_repo_manage
        from seaserv import seafile_api
        user = SimpleNamespace(username='native', is_staff=False, is_active=True)
        with patch.object(seafile_api, 'get_repo', return_value=SimpleNamespace(is_virtual=False)), \
             patch.object(seafile_api, 'check_permission', return_value='rw'), \
             patch('seahub.share.utils.is_repo_admin', return_value=False) as native:
            with self.assertRaises(PermissionError):
                require_repo_manage(user, RID)  # Native ordinary rw is not administrative.
            native.return_value = True
            require_repo_manage(user, RID)
        staff = SimpleNamespace(username='operator', is_staff=True, is_active=True,
                                admin_permissions=SimpleNamespace(can_manage_library=lambda: True))
        with patch.object(seafile_api, 'get_repo', return_value=SimpleNamespace(is_virtual=False)), \
             patch('seahub.share.utils.is_repo_admin') as native:
            require_repo_manage(staff, RID)
            native.assert_not_called()

    def test_public_rule_writer_uses_validated_three_permission_cas(self):
        request = dict(repo_id=RID, path='/folder', subject_type='user', namespace='user',
                       external_id='uid1', permission='invisible', inherit=True,
                       share_mode=False, expected=None,
                       revision='00000000-0000-4000-8000-000000000010')
        with patch('cloudfile_ext.v2.acl_http.publication_ready', return_value=True), \
             patch('cloudfile_ext.v2.acl_http.require_repo_manage'), \
             patch('cloudfile_ext.v2.acl_http.store') as rules, \
             patch('cloudfile_ext.v2.acl_http.settings') as settings:
            settings.CF_ACL_PROVIDER = 'etech'
            rules.return_value.mutate.return_value = request['revision']
            result = self.request(DirectoryRules, request, method='post')
            self.assertEqual(result.status_code, 200)
            self.assertEqual(rules.return_value.mutate.call_args.kwargs['expected'], None)
            self.assertEqual(rules.return_value.mutate.call_args.args[0].permission, 'invisible')
            request['permission'] = 'none'
            self.assertEqual(self.request(DirectoryRules, request, method='post').status_code, 400)
            self.assertEqual(rules.return_value.mutate.call_count, 1)

    def test_publication_requires_native_seafile_acl_without_extra_hub_toggle(self):
        import os
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from cloudfile_ext.v2.acl_http import publication_ready
        with TemporaryDirectory() as folder, \
             patch.dict(os.environ, {'SEAFILE_CENTRAL_CONF_DIR': folder}), \
             patch('cloudfile_ext.v2.acl_http.settings') as settings:
            conf = Path(folder) / 'seafile.conf'
            conf.write_text('[cloudfile]\nv2_acl_enabled=false\n')
            settings.CF_ACL_PUBLICATION_ENABLED = False
            self.assertFalse(publication_ready())
            conf.write_text('[cloudfile]\nv2_acl_enabled=true\n')
            self.assertTrue(publication_ready())  # redundant Hub toggle no longer blocks.
            conf.unlink()
            self.assertFalse(publication_ready())

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

    def test_directory_entries_tags_are_opt_in_and_failure_is_explicit(self):
        page = lambda: dict(data=[dict(repo_id=RID, path='/shared/a.txt', name='a.txt', kind='file', permission='r')],
                            root_path='/shared', next_offset=None)
        with patch('cloudfile_ext.v2.acl_http.Authority') as authority, \
                patch('cloudfile_ext.v2.acl_http.tag_display.tags_for_entries') as tags:
            authority.return_value.entries.side_effect = lambda *a, **k: page()
            result = self.request(DirectoryEntries, dict(repo_id=RID, path='/shared'))
            self.assertNotIn('tags_status', result.data)
            tags.assert_not_called()
            tags.return_value = {('/shared/a.txt', 'file'): [dict(file_tag_id=1, repo_tag_id=2, tag_name='t', tag_color='#f00')]}
            result = self.request(DirectoryEntries, dict(repo_id=RID, path='/shared', with_tags='true'))
            self.assertEqual(result.data['tags_status'], 'OK')
            self.assertEqual(result.data['data'][0]['tags'][0]['tag_name'], 't')
            tags.assert_called_with(RID, '/shared', [('/shared/a.txt', 'file')])
            tags.side_effect = OSError()
            result = self.request(DirectoryEntries, dict(repo_id=RID, path='/shared', with_tags='true'))
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.data['tags_status'], 'FAILED')
            self.assertIsNone(result.data['data'][0]['tags'])
            self.assertEqual(self.request(DirectoryEntries, dict(repo_id=RID, path='/shared', with_tags='1')).status_code, 400)

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
            authority.return_value.effective.return_value = Decision('invisible','/shared',True)
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
            authority.return_value.effective.return_value=Decision('invisible','/shared',True)
            result=InternalCheckFileOperationAccess.as_view()(request,repo_id=RID)
            self.assertEqual(result.status_code,403)
