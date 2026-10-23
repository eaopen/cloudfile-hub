"""Additive library ACL publisher contract; native services are test doubles."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from rest_framework.test import APIRequestFactory, force_authenticate

from cloudfile_ext.v2.acl_batch import CONTRACT, fingerprint
from cloudfile_ext.v2.acl_http import LibraryACLBatch
from cloudfile_ext.v2.acl_policy import Rule
from cloudfile_ext.v2.acl_store import RevisionConflict

RID = '00000000-0000-4000-8000-000000000001'
RULE = Rule(RID, '/shared', 'etech', 'user', 'user', 'uid', 'rw', True, True)
REVISION = '00000000-0000-4000-8000-000000000010'


class LibraryBatchHTTPTests(TestCase):
    def request(self, method, payload, *, authenticated=True):
        request = getattr(APIRequestFactory(), method)('/batch/', payload, format='json')
        if authenticated:
            force_authenticate(request, SimpleNamespace(
                username='native', is_authenticated=True, is_staff=False, is_active=True))
        return LibraryACLBatch.as_view()(request)

    def payload(self):
        return dict(
            repo_id=RID, expected_fingerprint=fingerprint(((RULE, REVISION),)),
            managed=[dict(path='/shared', subject_type='user', namespace='user', external_id='uid')],
            desired=[dict(path='/shared', subject_type='user', namespace='user', external_id='uid',
                          permission='r', inherit=True, share_mode=True)])

    def test_old_directory_route_and_additive_batch_get(self):
        with patch('cloudfile_ext.v2.acl_http.require_repo_manage') as auth, \
             patch('cloudfile_ext.v2.acl_http.store') as rules, \
             patch('cloudfile_ext.v2.acl_http.settings') as settings:
            settings.CF_ACL_PROVIDER = 'etech'
            rules.return_value.provider_snapshot.return_value = ((RULE, REVISION),)
            result = self.request('get', {'repo_id': RID})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.data['contract'], CONTRACT)
            self.assertEqual(result.data['fingerprint'], fingerprint(((RULE, REVISION),)))
            self.assertEqual(result.data['rules'][0]['revision'], REVISION)
            auth.assert_called_once()
            rules.return_value.provider_snapshot.assert_called_once_with(RID, 'etech')
            self.assertEqual(self.request('get', {'repo_id': RID, 'path': '/'}).status_code, 400)

    def test_batch_put_uses_server_provider_and_one_atomic_store_call(self):
        with patch('cloudfile_ext.v2.acl_http.require_repo_manage'), \
             patch('cloudfile_ext.v2.acl_http.store') as rules, \
             patch('cloudfile_ext.v2.acl_http.settings') as settings:
            settings.CF_ACL_PROVIDER = 'etech'
            rules.return_value.replace_owned.return_value = dict(
                fingerprint='a' * 64, inserted=0, updated=1, deleted=0, unchanged=0)
            result = self.request('put', self.payload())
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.data['updated'], 1)
            request = rules.return_value.replace_owned.call_args
            self.assertEqual(request.args, (RID, 'etech'))
            self.assertEqual(request.kwargs['managed'],
                             [('/shared', 'user', 'user', 'uid')])
            self.assertEqual(request.kwargs['desired'][0].permission, 'r')
            self.assertEqual(request.kwargs['desired'][0].provider, 'etech')

    def test_batch_resource_preview_reuses_one_snapshot_and_checks_every_directory(self):
        with patch('cloudfile_ext.v2.acl_http.require_repo_manage'), \
             patch('cloudfile_ext.v2.acl_http.store') as rules, \
             patch('seaserv.seafile_api.get_dir_id_by_path') as exists, \
             patch('cloudfile_ext.v2.acl_http.settings') as settings:
            settings.CF_ACL_PROVIDER = 'etech'
            exists.side_effect = lambda repo, path: 'd' * 40 if path == '/shared' else None
            rules.return_value.provider_snapshot.return_value = ((RULE, REVISION),)
            result = self.request('post', dict(repo_id=RID, paths=['/shared', '/missing']))
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.data['missing_paths'], ['/missing'])
            self.assertEqual(result.data['fingerprint'], fingerprint(((RULE, REVISION),)))
            self.assertEqual(exists.call_count, 2)
            self.assertEqual(rules.return_value.provider_snapshot.call_count, 1)
            self.assertEqual(self.request('post', dict(
                repo_id=RID, paths=['/shared', '/shared'])).status_code, 400)

    def test_bad_or_unmanaged_payload_never_reaches_sql(self):
        with patch('cloudfile_ext.v2.acl_http.require_repo_manage'), \
             patch('cloudfile_ext.v2.acl_http.store') as rules:
            invalid = self.payload()
            invalid['desired'][0]['permission'] = 'none'
            self.assertEqual(self.request('put', invalid).status_code, 400)
            invalid = self.payload()
            invalid['provider'] = 'other'  # Provider cannot be claimed by the caller.
            self.assertEqual(self.request('put', invalid).status_code, 400)
            invalid = self.payload()
            invalid['managed'][0]['path'] = '/'
            invalid['desired'][0]['share_mode'] = False
            rules.return_value.replace_owned.side_effect = ValueError('unmanaged')
            self.assertEqual(self.request('put', invalid).status_code, 400)

    def test_repo_admin_and_concurrent_snapshot_guards(self):
        with patch('cloudfile_ext.v2.acl_http.require_repo_manage',
                   side_effect=PermissionError()):
            self.assertEqual(self.request('put', self.payload()).status_code, 403)
        self.assertIn(self.request('put', self.payload(), authenticated=False).status_code, (401,403))
        with patch('cloudfile_ext.v2.acl_http.require_repo_manage'), \
             patch('cloudfile_ext.v2.acl_http.store') as rules:
            rules.return_value.replace_owned.side_effect = RevisionConflict()
            self.assertEqual(self.request('put', self.payload()).status_code, 409)

    def test_fingerprint_includes_revision_but_ignores_row_order(self):
        a = Rule(RID, '/a', 'etech', 'org', 'directory', 'dept1', 'invisible')
        rev = '00000000-0000-4000-8000-000000000011'
        self.assertEqual(fingerprint(((RULE, REVISION), (a, rev))),
                         fingerprint(((a, rev), (RULE, REVISION))))
        self.assertNotEqual(fingerprint(((RULE, REVISION),)),
                            fingerprint(((RULE, '00000000-0000-4000-8000-000000000011'),)))
