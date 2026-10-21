"""Native login redirects and first-login browser completion use real views."""
import subprocess
import sys
import textwrap


def test_browser_login_completion_preserves_api_contract():
    # Isolate host settings from other contract suites, while executing the
    # actual Django HTTP adapters with only the external login runtime mocked.
    subprocess.run([sys.executable, '-c', textwrap.dedent('''
        from django.conf import settings
        settings.configure(DEFAULT_CHARSET='utf-8', SITE_ROOT='/seafile/', ALLOWED_HOSTS=['testserver'])
        from django.test import RequestFactory
        from unittest.mock import MagicMock, patch
        from cloudfile_extensions.identity.resources import LoginResources
        from cloudfile_extensions.identity.runtime import LoginRuntime
        from cloudfile_extensions.identity.login import PendingLogin
        from cloudfile_extensions.identity.begin_http import LoginBeginView
        from cloudfile_extensions.identity.callback_http import LoginCallbackView
        resources = MagicMock(spec=LoginResources)
        runtime = MagicMock(spec=LoginRuntime)
        resources.runtime.return_value.__enter__.return_value = runtime
        resources.oidc = MagicMock()
        runtime.browser = MagicMock()
        runtime.login = MagicMock()
        resources.oidc.authorization_url = 'https://idp.example/authorize'
        runtime.browser.rotate.return_value = 'b' * 43
        runtime.login.begin.return_value = 'https://idp.example/authorize?state=fixture'
        factory = RequestFactory()
        view = LoginBeginView.as_view(resources=resources, return_path='/seafile/')
        response = view(factory.get('/begin/?next=/seafile/library/', secure=True))
        assert response.status_code == 302
        runtime.login.begin.assert_called_once_with('b' * 43, redirect='/seafile/')
        assert view(factory.get('/begin/?next=a&next=b', secure=True)).status_code == 400
        assert view(factory.get('/begin/?redirect=https://other.test', secure=True)).status_code == 400
        callback = LoginCallbackView.as_view(resources=resources)
        with patch('cloudfile_extensions.identity.callback_http.NativeOIDCSession') as native:
            native.return_value.complete.return_value = PendingLogin('job', 'p' * 43)
            for accept in ('text/html', 'application/json'):
                request = factory.get('/callback/', {'state':'s' * 43, 'code':'fixture'}, secure=True,
                    HTTP_ACCEPT=accept, HTTP_COOKIE='__Host-cloudfile-login-binding=' + 'b' * 43)
                response = callback(request)
                assert response.status_code == 202, response.content
                assert response['Cache-Control'] == 'no-store, max-age=0'
                assert response['Referrer-Policy'] == 'no-referrer'
                if accept == 'text/html':
                    body = response.content.decode()
                    assert 'text/html' in response['Content-Type']
                    assert '/seafile/api/v2.1/cloudfile/extensions/identity/v1/pending/' in body
                    assert 'CloudFilePending ' in body
                    assert 'localStorage' not in body and 'sessionStorage' not in body
                    assert "connect-src 'self'" in response['Content-Security-Policy']
                else:
                    import json
                    assert json.loads(response.content)['status_token'] == 'p' * 43
    ''')], check=True)
