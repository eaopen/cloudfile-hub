"""Exercise compatibility views without changing native permission identities."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock
import pytest


@pytest.fixture
def runtime(monkeypatch):
    import sys

    def response(data, status=200):
        return NS(data=data, status_code=status)

    class NativeAccount:
        def get(self, request, format=None):
            return response({'email': request.user.username, 'name': 'Employee'})

    native_post = Mock(return_value=response({'error_msg': 'missing'}, 404))

    class NativeToken:
        def post(self, request):
            return native_post(request)

    settings = NS()
    user = NS(username='opaque@auth.local', is_active=True)
    users = Mock()
    users.objects.get.return_value = user
    token = Mock(return_value=NS(key='test-token'))
    resolve = Mock(return_value=user.username)
    public = Mock(return_value='10220942@auth.local')
    modules = {
        'django.conf': NS(settings=settings),
        'rest_framework.response': NS(Response=response),
        'seahub.api2.views': NS(AccountInfo=NativeAccount),
        'seahub.api2.utils': NS(api_error=lambda status, msg: response({'error_msg': msg}, status), get_token_v1=token),
        'seahub.base.accounts': NS(User=users),
        'seahub.api2.endpoints.admin.generate_user_auth_token': NS(AdminGenerateUserAuthToken=NativeToken),
        'cloudfile_ext.library_admin_identity': NS(resolve_subject=resolve, public_subject=public),
    }
    for name, value in modules.items():
        monkeypatch.setitem(sys.modules, name, value)

    def load(name):
        spec = importlib.util.spec_from_file_location('cloudfile_ext.sso.' + name,
            Path(__file__).parents[1] / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    account, tokens = load('account_api'), load('token_api')
    directory = Mock(return_value=user.username)
    monkeypatch.setattr(tokens, 'resolve_employee_token', directory)
    return NS(settings=settings, user=user, token=token, resolve=resolve,
              public=public, native_post=native_post, directory=directory,
              account=account.EmployeeAccountInfo(), tokens=tokens.EmployeeTokenView(),
              request=NS(user=user, data={'email': '10220942@auth.local'}))


@pytest.mark.parametrize('flag', [None, False, 'false', 'true', 1])
def test_only_boolean_true_enables_bridges(runtime, flag):
    r = runtime
    r.settings.CF_EAP_ACCOUNT_INFO_IDENTITY_BRIDGE = flag
    r.settings.CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE = flag
    assert r.account.get(r.request).data['email'] == r.user.username
    assert r.tokens.post(r.request).status_code == 404
    r.public.assert_not_called()
    r.resolve.assert_not_called()


def test_alias_presentation_keeps_permission_identity(runtime):
    r = runtime
    r.settings.CF_EAP_ACCOUNT_INFO_IDENTITY_BRIDGE = True
    result = r.account.get(r.request)
    assert result.data == {'email': '10220942@auth.local', 'native_email': 'opaque@auth.local', 'name': 'Employee'}
    assert r.request.user.username == 'opaque@auth.local'


def test_reviewed_alias_reuses_native_token_without_directory(runtime):
    r = runtime
    r.settings.CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE = True
    assert r.tokens.post(r.request).status_code == 200
    r.token.assert_called_once_with('opaque@auth.local')
    r.directory.assert_not_called()
    r.native_post.assert_not_called()


def test_stale_reviewed_alias_cannot_fall_back(runtime):
    r = runtime
    r.settings.CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE = True
    r.settings.CF_EAP_ACCOUNT_INFO_IDENTITY_BRIDGE = True
    r.resolve.side_effect = ValueError('sensitive internal detail')
    r.public.side_effect = ValueError('sensitive internal detail')
    for result in (r.tokens.post(r.request), r.account.get(r.request)):
        assert result.status_code == 503
        assert 'sensitive' not in str(result.data)
        assert 'token' not in result.data
    r.directory.assert_not_called()
    r.token.assert_not_called()


@pytest.mark.parametrize('active,native', [(False, 'opaque@auth.local'), (True, 'other@auth.local')])
def test_inactive_or_reassigned_native_account_refuses_token(runtime, active, native):
    r = runtime
    r.settings.CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE = True
    r.user.is_active, r.user.username = active, native
    assert r.tokens.post(r.request).status_code == 503
    r.token.assert_not_called()


def test_unconfigured_account_keeps_native_response(runtime):
    r = runtime
    r.settings.CF_EAP_ACCOUNT_INFO_IDENTITY_BRIDGE = True
    r.public.return_value = r.user.username
    assert r.account.get(r.request).data == {'email': r.user.username, 'name': 'Employee'}


def test_unconfigured_missing_alias_uses_authenticated_directory(runtime):
    r = runtime
    r.settings.CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE = True
    r.resolve.return_value = None
    assert r.tokens.post(r.request).status_code == 200
    r.directory.assert_called_once_with('10220942@auth.local')


def test_native_errors_other_than_missing_do_not_trigger_directory(runtime):
    r = runtime
    r.settings.CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE = True
    r.resolve.return_value = None
    r.native_post.return_value = NS(data={'error_msg': 'inactive'}, status_code=400)
    assert r.tokens.post(r.request).status_code == 400
    r.directory.assert_not_called()
