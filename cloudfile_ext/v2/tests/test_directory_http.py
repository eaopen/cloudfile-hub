"""enterprise Directory MVP identity seams reuse native accounts and reject mismatched bindings."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from rest_framework.test import APIRequestFactory, force_authenticate
from cloudfile_ext.v2.http import IdentityResolve
from seahub.oauth import views


class EnterpriseDirectoryIdentityLookupTests(TestCase):
    def request(self, data, staff=True):
        request = APIRequestFactory().post('/identities/resolve/', data, format='json')
        force_authenticate(request, SimpleNamespace(is_staff=staff, is_authenticated=True))
        return IdentityResolve.as_view()(request)

    def test_existing_uid_keeps_opaque_native_username(self):
        with patch('cloudfile_ext.v2.http.Profile.objects.filter', return_value=Mock(values_list=Mock(return_value=[('opaque@auth.local', '417137619324108800')]))), \
                patch('cloudfile_ext.v2.http.User.objects.get', return_value=SimpleNamespace(username='opaque@auth.local', is_active=True)), \
                patch('cloudfile_ext.v2.http.Profile.objects.get_profile_by_user', return_value=SimpleNamespace(login_id='417137619324108800')):
            response = self.request({'external_user_id': '417137619324108800', 'login_id': '417137619324108800'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['email'], 'opaque@auth.local')
        self.assertEqual(response.data['login_id'], '417137619324108800')

    def test_uid_mismatch_is_rejected_before_lookup(self):
        with patch('cloudfile_ext.v2.http.Profile.objects.filter') as lookup:
            self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'other'}).status_code, 400)
            lookup.assert_not_called()

    def test_non_admin_cannot_resolve_other_users(self):
        self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}, staff=False).status_code, 403)

    def test_unknown_uid_requires_trusted_directory_preparation(self):
        from cloudfile_ext.v2.errors import IdentityUnavailable
        with patch('cloudfile_ext.v2.http.Profile.objects.filter', return_value=Mock(values_list=Mock(return_value=[]))), \
                patch('cloudfile_ext.v2.directory_adapter.prepare_user', side_effect=IdentityUnavailable()) as prepare, \
                patch('cloudfile_ext.v2.http.User.objects.get') as user:
            self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}).status_code, 503)
            prepare.assert_called_once_with('uid')
            user.assert_not_called()

    def test_prepared_user_is_read_back_and_uid_alias_is_rejected(self):
        with patch('cloudfile_ext.v2.http.Profile.objects.filter', return_value=Mock(values_list=Mock(return_value=[]))), \
                patch('cloudfile_ext.v2.directory_adapter.prepare_user', return_value='new@auth.local'), \
                patch('cloudfile_ext.v2.http.Profile.objects.get_profile_by_user', return_value=SimpleNamespace(login_id='uid')) as profile, \
                patch('cloudfile_ext.v2.http.User.objects.get', return_value=SimpleNamespace(username='new@auth.local', is_active=True)):
            self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}).status_code, 200)
            profile.return_value.login_id = 'UID'
            self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}).status_code, 409)

    def test_ambiguous_or_case_aliased_uid_cannot_prepare_or_select_a_user(self):
        for rows in ([('a@auth.local', 'uid'), ('b@auth.local', 'uid')], [('a@auth.local', 'UID')]):
            with patch('cloudfile_ext.v2.http.Profile.objects.filter', return_value=Mock(values_list=Mock(return_value=rows))), \
                    patch('cloudfile_ext.v2.directory_adapter.prepare_user') as prepare:
                self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}).status_code, 409)
                prepare.assert_not_called()

    def test_disabled_reserved_or_changed_native_account_is_rejected(self):
        for username, active, returned in (('old@auth.local', False, 'old@auth.local'),
                                           ('cfadmin@auth.local', True, 'cfadmin@auth.local'),
                                           ('old@auth.local', True, 'OLD@auth.local')):
            with patch('cloudfile_ext.v2.http.Profile.objects.filter', return_value=Mock(values_list=Mock(return_value=[(username, 'uid')]))), \
                    patch('cloudfile_ext.v2.http.Profile.objects.get_profile_by_user', return_value=SimpleNamespace(login_id='uid')), \
                    patch('cloudfile_ext.v2.http.User.objects.get', return_value=SimpleNamespace(username=returned, is_active=active)):
                self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}).status_code, 409)

    def test_request_alias_is_ignored(self):
        from cloudfile_ext.v2.errors import IdentityConflict
        with patch('cloudfile_ext.v2.http.Profile.objects.filter', return_value=Mock(values_list=Mock(return_value=[]))), \
                patch('cloudfile_ext.v2.directory_adapter.prepare_user', side_effect=IdentityConflict()) as prepare:
            self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid', 'login_email': 'attacker@auth.local'}).status_code, 409)
            prepare.assert_called_once_with('uid')


class EnterpriseDirectoryOAuthBindingTests(TestCase):
    def test_oidc_login_adds_nonce_and_native_oauth_clears_oidc_mode(self):
        from cloudfile_ext.v2.oidc import oidc_login
        request = APIRequestFactory().get('/cfile/oidc/login/')
        request.session = {}
        session = Mock()
        session.authorization_url.return_value = ('https://idp.example.test/authorize', 'state')
        with patch('cloudfile_ext.v2.oidc.configuration', return_value=('issuer', 'jwks')), \
                patch.object(views, 'OAuth2Session', return_value=session):
            self.assertEqual(oidc_login(request).status_code, 302)
            self.assertEqual(request.session['oauth_protocol'], 'oidc')
            self.assertTrue(request.session['oauth_nonce'])
            self.assertEqual(session.authorization_url.call_args.kwargs['nonce'], request.session['oauth_nonce'])
            del request._cloudfile_oidc
            self.assertEqual(views.oauth_login(request).status_code, 302)
            self.assertEqual(request.session['oauth_protocol'], 'oauth2')
            self.assertNotIn('oauth_nonce', request.session)

    def callback(self, oauth_binding, profile_username, profile_uid, *, oidc=False, invalid_token=False,
                 userinfo_sub='trusted-sub', missing_uid=False, generic=False, id_uid='business-uid'):
        request = APIRequestFactory().get('/cfile/oauth/callback/?code=test&state=expected')
        request.session = {'oauth_state': 'expected'}
        if oidc:
            request.session.update(oauth_protocol='oidc', oauth_nonce='nonce')
        session = Mock()
        session._client = SimpleNamespace(token={})
        session.fetch_token.return_value = {}
        session.get.return_value.status_code = 200
        session.get.return_value.json.return_value = {'sub': userinfo_sub, 'userId': 'business-uid'}
        if missing_uid:
            session.get.return_value.json.return_value = {'sub': userinfo_sub}
        profile = SimpleNamespace(login_id=profile_uid, nickname='', contact_email='', save=Mock())
        from cloudfile_ext.v2.oauth_identity import UIDBindingError
        conflicting = (oauth_binding is not None and oauth_binding.username != profile_username)
        conflicting = conflicting or profile_uid != 'business-uid'
        from cloudfile_ext.v2.errors import IdentityUnavailable
        with patch('cloudfile_ext.v2.oidc.configuration', return_value=('https://idp.example.test/', 'https://idp.example.test/jwks')), \
                patch('cloudfile_ext.v2.oidc.verify_id_token', return_value=({'sub': 'trusted-sub'} if id_uid is None else {'sub': 'trusted-sub', 'userId': id_uid}),
                      side_effect=IdentityUnavailable('rejected') if invalid_token else None) as verify, \
                patch.object(views, 'OAuth2Session', return_value=session), \
                patch.object(views, 'OAUTH_ATTRIBUTE_MAP', ({'sub': (True, 'uid')} if generic else {'sub': (True, 'uid'), 'userId': (False, 'login_id')})), \
                patch('cloudfile_ext.v2.oauth_identity.bind_existing_uid',
                      return_value=profile_username,
                      side_effect=UIDBindingError('UID conflict') if conflicting else None) as bind, \
                patch.object(views.Profile.objects, 'get_or_create', return_value=(profile, False)), \
                patch.object(views.auth, 'authenticate', return_value=SimpleNamespace(
                    username='existing@auth.local', is_active=True)) as authenticate, \
                patch.object(views.auth, 'login'), \
                patch.object(views, 'get_api_token', return_value=SimpleNamespace(key='test-token')), \
                patch.object(views, 'get_service_url', return_value='https://files.example.test'), \
                patch.object(views, 'render_error', return_value='binding-error'):
            response = views.oauth_callback(request)
        self.assertEqual(session.fetch_token.call_args.kwargs['authorization_response'],
                         'https://files.example.test/cfile/oauth/callback/?code=test&state=expected')
        self.assertNotIn('oauth_state', request.session)
        if oidc:
            verify.assert_called_once()
            self.assertNotIn('oauth_nonce', request.session)
        return response, authenticate, bind

    def test_cloudfile_sso_cannot_keep_session_when_uid_refresh_fails(self):
        from cloudfile_ext.v2.errors import IdentityUnavailable
        with patch.object(views.settings, 'CF_DIRECTORY_URL',
                          'https://directory.example.test/directory', create=True), \
             patch('cloudfile_ext.v2.directory_adapter.ensure_subject',
                   side_effect=IdentityUnavailable('offline')), \
             patch.object(views.auth, 'logout') as logout:
            response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid')
        self.assertEqual(response, 'binding-error')
        authenticate.assert_called_once()
        logout.assert_not_called()

    def test_first_oauth_login_reuses_existing_business_uid_account(self):
        response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid')
        self.assertEqual(response.status_code, 302)
        authenticate.assert_called_once_with(remote_user='existing@auth.local')
        bind.assert_called_once_with(uid='business-uid', provider=views.OAUTH_PROVIDER, subject='trusted-sub')

    def test_conflicting_oauth_and_business_uid_bindings_cannot_rebind(self):
        response, authenticate, bind = self.callback(SimpleNamespace(username='other@auth.local'), 'existing@auth.local', 'other-uid')
        self.assertEqual(response, 'binding-error')
        authenticate.assert_not_called()
        bind.assert_called_once()

    def test_oidc_reuses_the_same_native_uid_account_and_session(self):
        response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', oidc=True)
        self.assertEqual(response.status_code, 302)
        authenticate.assert_called_once_with(remote_user='existing@auth.local')
        bind.assert_called_once_with(uid='business-uid', provider=views.OAUTH_PROVIDER, subject='trusted-sub')

    def test_oidc_invalid_token_or_mismatched_userinfo_cannot_authenticate(self):
        for options in ({'invalid_token': True}, {'userinfo_sub': 'other-sub'}):
            with self.subTest(options=options):
                response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', oidc=True, **options)
                self.assertEqual(response, 'binding-error')
                authenticate.assert_not_called()
                bind.assert_not_called()

    def test_native_uid_collation_alias_cannot_be_claimed(self):
        response, authenticate, bind = self.callback(None, 'existing@auth.local', 'BUSINESS-UID')
        self.assertEqual(response, 'binding-error')
        authenticate.assert_not_called()
        bind.assert_called_once()

    def test_missing_optional_trusted_uid_cannot_fall_back_to_ce_signup(self):
        response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', missing_uid=True)
        self.assertEqual(response, 'binding-error')
        authenticate.assert_not_called()

    def test_directory_config_cannot_enter_employee_claim_compatibility_path(self):
        with patch.object(views.settings, 'CF_DIRECTORY_URL', 'https://directory.test', create=True):
            response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', generic=True)
        self.assertEqual(response, 'binding-error')
        authenticate.assert_not_called()
        bind.assert_not_called()

    def test_generic_ce_oauth_without_directory_keeps_existing_provider_resolution(self):
        with patch.object(views.settings, 'CF_DIRECTORY_URL', '', create=True), \
                patch.object(views.SocialAuthUser.objects, 'get_by_provider_and_uid', return_value=SimpleNamespace(username='existing@auth.local')):
            response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', generic=True)
        self.assertEqual(response.status_code, 302)
        authenticate.assert_called_once_with(remote_user='existing@auth.local')
        bind.assert_not_called()

    def test_signed_oidc_identity_uses_v2_jit_and_oauth_remains_reuse_only(self):
        with patch.object(views.settings, 'CF_DIRECTORY_URL', 'https://directory.test', create=True), \
                patch('cloudfile_ext.v2.directory_adapter.provision_oidc_user', return_value='existing@auth.local') as provision, \
                patch('cloudfile_ext.v2.directory_adapter.ensure_subject'):
            response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', oidc=True)
        self.assertEqual(response.status_code, 302)
        provision.assert_called_once_with(uid='business-uid', provider=views.OAUTH_PROVIDER, subject='trusted-sub')
        bind.assert_not_called()

    def test_missing_signed_business_uid_cannot_provision_even_with_userinfo_uid(self):
        with patch.object(views.settings, 'CF_DIRECTORY_URL', 'https://directory.test', create=True), \
                patch('cloudfile_ext.v2.directory_adapter.provision_oidc_user') as provision:
            response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', oidc=True, id_uid=None)
        self.assertEqual(response, 'binding-error')
        provision.assert_not_called()
        authenticate.assert_not_called()
        bind.assert_not_called()

    def test_missing_state_cannot_fetch_tokens(self):
        for saved, supplied in (({}, 'expected'), ({'oauth_state': 'expected'}, '错误-state')):
            request = APIRequestFactory().get('/cfile/oauth/callback/', {'code': 'test', 'state': supplied})
            request.session = saved
            with patch.object(views, 'OAuth2Session') as session, \
                    patch.object(views, 'render_error', return_value='state-error'):
                self.assertEqual(views.oauth_callback(request), 'state-error')
            session.assert_not_called()


class EnterpriseDirectoryGroupPreparationTests(TestCase):
    def setUp(self):
        lookup = patch('cloudfile_ext.v2.directory_adapter.lookup_group', return_value=None)
        self.lookup = lookup.start()
        self.addCleanup(lookup.stop)

    def request(self, external, staff=True):
        from cloudfile_ext.v2.http import GroupResolve
        request = APIRequestFactory().post('/groups/resolve/', {'external_group_id': external}, format='json')
        force_authenticate(request, SimpleNamespace(is_staff=staff, is_authenticated=True))
        return GroupResolve.as_view()(request)

    def test_group_is_proved_by_trusted_catalog_and_not_name(self):
        with patch('cloudfile_ext.v2.directory_adapter.prepare_group', return_value=42) as prepare:
            self.assertEqual(self.request('role:r1').data, {'group_id': 42})
            prepare.assert_called_once_with('role:r1')
            self.assertEqual(self.request('role:r1', staff=False).status_code, 403)

    def test_catalog_failure_and_conflicting_identity_deny(self):
        from cloudfile_ext.v2.errors import IdentityUnavailable, IdentityConflict
        with patch('cloudfile_ext.v2.directory_adapter.prepare_group', side_effect=IdentityUnavailable()):
            self.assertEqual(self.request('org1').status_code, 503)
        with patch('cloudfile_ext.v2.directory_adapter.prepare_group', side_effect=IdentityConflict()):
            self.assertEqual(self.request('org1').status_code, 409)

    def test_existing_mapping_allows_revocation_when_directory_entity_is_gone(self):
        self.lookup.return_value=42
        with patch('cloudfile_ext.v2.directory_adapter.prepare_group',side_effect=AssertionError('must not reprovision')):
            self.assertEqual(self.request('role:r1').data,{'group_id':42})
