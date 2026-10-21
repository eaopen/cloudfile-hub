"""SSO login CSRF rotation: actual Django response cookie and native OIDC success boundary."""
import subprocess
import sys
import textwrap


def test_csrf_rotation_publishes_seafile_cookie_without_new_configuration():
    subprocess.run([sys.executable, "-c", textwrap.dedent("""
        from django.conf import settings
        settings.configure(SECRET_KEY='fixture-only',
                           DEFAULT_CHARSET='utf-8', CSRF_COOKIE_NAME='sfcsrftoken',
                           CSRF_COOKIE_SAMESITE='Lax')
        from django.http import HttpResponseRedirect
        from django.middleware.csrf import CsrfViewMiddleware, get_token, rotate_token
        from django.test import RequestFactory

        request = RequestFactory().get('/oauth/callback/')
        original = get_token(request)
        rotate_token(request)
        assert get_token(request) != original
        response = CsrfViewMiddleware(lambda req: HttpResponseRedirect('/')).process_response(
            request, HttpResponseRedirect('/portal/'))
        assert response.status_code == 302
        assert response.cookies['sfcsrftoken'].value
        assert response.cookies['sfcsrftoken']['samesite'] == 'Lax'
        assert response['Location'] == '/portal/'
    """)], check=True)


def test_native_oidc_rotates_only_after_successful_session_finalization():
    subprocess.run([sys.executable, "-c", textwrap.dedent("""
        import sys
        from contextlib import nullcontext
        from datetime import datetime, timedelta, timezone
        from types import SimpleNamespace as NS
        from unittest.mock import MagicMock, Mock, patch
        from django.conf import settings
        from django.test import RequestFactory
        from cloudfile_extensions.identity.runtime import LoginRuntime
        from cloudfile_extensions.identity.login import PreparedLogin
        from cloudfile_extensions.identity.native_session import BACKEND, NativeOIDCSession
        from cloudfile_extensions.common.errors import ContractError

        settings.configure(SECRET_KEY='fixture-only', DEFAULT_CHARSET='utf-8',
            SESSION_ENGINE='django.contrib.sessions.backends.db',
            AUTHENTICATION_BACKENDS=(BACKEND,))
        request = RequestFactory().get('/callback/')
        request.session = MagicMock()
        request.session.get_expiry_date.return_value = datetime.now(timezone.utc) + timedelta(hours=1)

        runtime = MagicMock(spec=LoginRuntime)
        runtime.login = MagicMock()
        runtime.connection = MagicMock()
        runtime.browser = MagicMock()
        runtime.browser.assert_active = Mock()
        runtime.flow = NS(config=NS(issuer='https://idp.test/', client_id='cloudfile', end_session_url=None))
        runtime.login.complete.return_value = PreparedLogin(user_id='u1', username='u1@auth.local',
            context_epoch='a' * 32, redirect='/portal/', expires_at=9999999999)
        preparation = MagicMock()
        preparation.actor = 'u1'
        preparation.state.provider = 'test'
        runtime.preparation.return_value = preparation
        user = NS(username='u1@auth.local')
        stub_auth = NS(login=Mock())
        stub_accounts = NS(AnonymousUser=Mock())
        stub_mfa = NS(two_factor_auth_enabled=lambda _: False)
        modules = {'seahub.auth': stub_auth, 'seahub.auth.models': stub_accounts,
                   'seahub.utils.two_factor_auth': stub_mfa}
        with patch.dict(sys.modules, modules), \
             patch('cloudfile_extensions.identity.native_session.transport_allowed', return_value=True), \
             patch('cloudfile_extensions.identity.native_session.CloudFileOIDCBackend') as backend, \
             patch('cloudfile_extensions.identity.native_session.scope_locks', return_value=nullcontext()), \
             patch('cloudfile_extensions.identity.native_session.prepared_session_guard',
                   return_value=nullcontext(Mock())), \
             patch('cloudfile_extensions.identity.native_session.OIDCSessionIndex') as index, \
             patch('cloudfile_extensions.identity.native_session.rotate_token') as rotate:
            backend.return_value.get_user.return_value = user
            index.return_value.scope = {'scope': 'fixture'}
            index.return_value.scope_hash = 'a' * 64
            index.return_value._hash.return_value = 'a' * 64
            response = NativeOIDCSession().complete(request, runtime, state='state', code='code', binding='b')
            assert response.status_code == 302
            assert response['Location'] == '/portal/'
            stub_auth.login.assert_called_once_with(request, user)
            rotate.assert_called_once_with(request)
            runtime.browser.clear.assert_called_once_with('b', response)

            rotate.reset_mock()
            request.session.reset_mock()
            backend.return_value.get_user.return_value = None
            try:
                NativeOIDCSession().complete(request, runtime, state='state', code='code', binding='b')
                raise AssertionError('inactive user was admitted')
            except ContractError:
                pass
            rotate.assert_not_called()
    """)], check=True)
