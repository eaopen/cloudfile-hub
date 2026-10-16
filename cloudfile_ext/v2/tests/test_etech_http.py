"""Etech MVP identity seams reuse native accounts and reject mismatched bindings."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from rest_framework.test import APIRequestFactory, force_authenticate
from cloudfile_ext.v2.http import IdentityResolve
from seahub.oauth import views


class EtechIdentityLookupTests(TestCase):
    def request(self, data, staff=True):
        request = APIRequestFactory().post('/identities/resolve/', data, format='json')
        force_authenticate(request, SimpleNamespace(is_staff=staff, is_authenticated=True))
        return IdentityResolve.as_view()(request)

    def test_existing_uid_keeps_opaque_native_username(self):
        with patch('cloudfile_ext.v2.http.Profile.objects.get_username_by_login_id', return_value='opaque@auth.local'), \
                patch('cloudfile_ext.v2.http.User.objects.get', return_value=SimpleNamespace(username='opaque@auth.local', is_active=True)):
            response = self.request({'external_user_id': '417137619324108800', 'login_id': '417137619324108800'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['email'], 'opaque@auth.local')
        self.assertEqual(response.data['login_id'], '417137619324108800')

    def test_uid_mismatch_is_rejected_before_lookup(self):
        with patch('cloudfile_ext.v2.http.Profile.objects.get_username_by_login_id') as lookup:
            self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'other'}).status_code, 400)
            lookup.assert_not_called()

    def test_non_admin_cannot_resolve_other_users(self):
        self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}, staff=False).status_code, 403)

    def test_unknown_uid_does_not_provision_user(self):
        with patch('cloudfile_ext.v2.http.Profile.objects.get_username_by_login_id', return_value=None), \
                patch('cloudfile_ext.v2.http.User.objects.get') as user:
            self.assertEqual(self.request({'external_user_id': 'uid', 'login_id': 'uid'}).status_code, 404)
            user.assert_not_called()


class EtechOAuthBindingTests(TestCase):
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
                 userinfo_sub='trusted-sub'):
        request = APIRequestFactory().get('/cfile/oauth/callback/?code=test&state=expected')
        request.session = {'oauth_state': 'expected'}
        if oidc:
            request.session.update(oauth_protocol='oidc', oauth_nonce='nonce')
        session = Mock()
        session._client = SimpleNamespace(token={})
        session.fetch_token.return_value = {}
        session.get.return_value.status_code = 200
        session.get.return_value.json.return_value = {'sub': userinfo_sub, 'userId': 'business-uid'}
        profile = SimpleNamespace(login_id=profile_uid, save=Mock())
        from cloudfile_ext.v2.errors import IdentityUnavailable
        with patch('cloudfile_ext.v2.oidc.configuration', return_value=('https://idp.example.test/', 'https://idp.example.test/jwks')), \
                patch('cloudfile_ext.v2.oidc.verify_id_token', return_value={'sub': 'trusted-sub'},
                      side_effect=IdentityUnavailable('rejected') if invalid_token else None) as verify, \
                patch.object(views, 'OAuth2Session', return_value=session), \
                patch.object(views, 'OAUTH_ATTRIBUTE_MAP', {'sub': (True, 'uid'), 'userId': (True, 'login_id')}), \
                patch.object(views.SocialAuthUser.objects, 'get_by_provider_and_uid', return_value=oauth_binding), \
                patch.object(views.SocialAuthUser.objects, 'add') as bind, \
                patch.object(views.Profile.objects, 'get_username_by_login_id', return_value=profile_username), \
                patch.object(views.Profile.objects, 'get_profile_by_user', return_value=profile), \
                patch.object(views.auth, 'authenticate', return_value=SimpleNamespace(username='existing@auth.local')) as authenticate, \
                patch.object(views.auth, 'login'), \
                patch.object(views, 'get_api_token', return_value=SimpleNamespace(key='test-token')), \
                patch.object(views, 'get_service_url', return_value='https://files.example.test/cfile'), \
                patch.object(views, 'render_error', return_value='binding-error'):
            response = views.oauth_callback(request)
        self.assertEqual(session.fetch_token.call_args.kwargs['authorization_response'],
                         'https://files.example.test/cfile/oauth/callback/?code=test&state=expected')
        self.assertNotIn('oauth_state', request.session)
        if oidc:
            verify.assert_called_once()
            self.assertNotIn('oauth_nonce', request.session)
        return response, authenticate, bind

    def test_first_oauth_login_reuses_existing_business_uid_account(self):
        response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid')
        self.assertEqual(response.status_code, 302)
        authenticate.assert_called_once_with(remote_user='existing@auth.local')
        bind.assert_called_once_with('existing@auth.local', views.OAUTH_PROVIDER, 'trusted-sub')

    def test_conflicting_oauth_and_business_uid_bindings_cannot_rebind(self):
        response, authenticate, bind = self.callback(SimpleNamespace(username='other@auth.local'), 'existing@auth.local', 'other-uid')
        self.assertEqual(response, 'binding-error')
        authenticate.assert_not_called()
        bind.assert_not_called()

    def test_oidc_reuses_the_same_native_uid_account_and_session(self):
        response, authenticate, bind = self.callback(None, 'existing@auth.local', 'business-uid', oidc=True)
        self.assertEqual(response.status_code, 302)
        authenticate.assert_called_once_with(remote_user='existing@auth.local')
        bind.assert_called_once_with('existing@auth.local', views.OAUTH_PROVIDER, 'trusted-sub')

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
        bind.assert_not_called()

    def test_missing_state_cannot_fetch_tokens(self):
        for saved, supplied in (({}, 'expected'), ({'oauth_state': 'expected'}, '错误-state')):
            request = APIRequestFactory().get('/cfile/oauth/callback/', {'code': 'test', 'state': supplied})
            request.session = saved
            with patch.object(views, 'OAuth2Session') as session, \
                    patch.object(views, 'render_error', return_value='state-error'):
                self.assertEqual(views.oauth_callback(request), 'state-error')
            session.assert_not_called()


class EtechGroupLookupTests(TestCase):
    def request(self, external, rows=(), staff=True):
        from cloudfile_ext.v2.http import GroupResolve
        request = APIRequestFactory().post('/groups/resolve/', {'external_group_id': external}, format='json')
        force_authenticate(request, SimpleNamespace(is_staff=staff, is_authenticated=True))
        with patch('django.db.connection.cursor') as cursor, \
                patch('seahub.utils.db_api.SeafileDB', return_value=SimpleNamespace(db_name='seafile_db')):
            cursor.return_value.__enter__.return_value.fetchall.return_value = rows
            response = GroupResolve.as_view()(request)
        return response, cursor

    def test_existing_mapping_uses_native_group_without_members(self):
        response, cursor = self.request('2001', [(583,)])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'group_id': 583})
        self.assertEqual(cursor.return_value.__enter__.return_value.execute.call_args.args[1],
                         ('etech', 'dept', 'org', '2001'))

    def test_role_namespace_is_distinct(self):
        response, cursor = self.request('role:2001', [(584,)])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cursor.return_value.__enter__.return_value.execute.call_args.args[1],
                         ('etech', 'group', 'role', '2001'))

    def test_missing_and_conflicting_mappings_are_not_guessed(self):
        self.assertEqual(self.request('2001')[0].status_code, 404)
        self.assertEqual(self.request('2001', [(583,), (584,)])[0].status_code, 409)

    def test_non_admin_cannot_resolve_mapping(self):
        response, cursor = self.request('2001', staff=False)
        self.assertEqual(response.status_code, 403)
        cursor.assert_not_called()
