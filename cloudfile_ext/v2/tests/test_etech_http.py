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
    def callback(self, oauth_binding, profile_username, profile_uid):
        request = APIRequestFactory().get('/oauth/callback/?code=test')
        request.session = {}
        session = Mock()
        session._client = SimpleNamespace(token={})
        session.fetch_token.return_value = {}
        session.get.return_value.json.return_value = {'sub': 'trusted-sub', 'userId': 'business-uid'}
        profile = SimpleNamespace(login_id=profile_uid, save=Mock())
        with patch.object(views, 'OAuth2Session', return_value=session), \
                patch.object(views, 'OAUTH_ATTRIBUTE_MAP', {'sub': (True, 'uid'), 'userId': (True, 'login_id')}), \
                patch.object(views.SocialAuthUser.objects, 'get_by_provider_and_uid', return_value=oauth_binding), \
                patch.object(views.SocialAuthUser.objects, 'add') as bind, \
                patch.object(views.Profile.objects, 'get_username_by_login_id', return_value=profile_username), \
                patch.object(views.Profile.objects, 'get_profile_by_user', return_value=profile), \
                patch.object(views.auth, 'authenticate', return_value=SimpleNamespace(username='existing@auth.local')) as authenticate, \
                patch.object(views.auth, 'login'), \
                patch.object(views, 'get_api_token', return_value=SimpleNamespace(key='test-token')), \
                patch.object(views, 'render_error', return_value='binding-error'):
            response = views.oauth_callback(request)
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
