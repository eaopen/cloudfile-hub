"""Deployed OAuth bridge: UID authority, explicit legacy upgrades and collisions."""
import pytest
from cloudfile_ext.sso.eap_oauth import identity_pair, choose_native, IdentityConflict


def test_uid_and_employee_are_distinct_from_subject_and_email():
    assert identity_pair({'userId': '1874256721845686275', 'preferred_username': '10280993',
                          'sub': 'opaque-sub', 'email': 'shared@example.com'}) == ('1874256721845686275', '10280993')


@pytest.mark.parametrize('uid,employee', [(123, '1022'), ('emp', '1022'), ('123', 'cfadmin'),
                                         ('123', ''), ('123', 'evil@other'), ('123', '../x')])
def test_invalid_rows_refuse_only_their_own_login(uid, employee):
    with pytest.raises(IdentityConflict):
        identity_pair({'userId': uid, 'preferred_username': employee})


def test_exact_uid_reuses_existing_native_name_without_employee_lookup():
    assert choose_native('123', '1022', None, None, [('opaque@auth.local', '123')]) == 'opaque@auth.local'
    assert choose_native('123', '1022', None, None, []) is None


def test_verified_existing_sub_can_upgrade_legacy_employee_login_id():
    assert choose_native('123', '1022', 'old@auth.local', ('old@auth.local', '1022'), []) == 'old@auth.local'
    assert choose_native('123', '1022', 'old@auth.local', ('old@auth.local', '123'), [('old@auth.local', '123')]) == 'old@auth.local'


@pytest.mark.parametrize('profile,uid_rows', [
    (('old@auth.local', '456'), []),
    (('old@auth.local', '123'), [('other@auth.local', '123')]),
    (('old@auth.local', '123'), [('old@auth.local', '123'), ('other@auth.local', '123')])])
def test_changed_uid_or_disagreement_never_merges_accounts(profile, uid_rows):
    with pytest.raises(IdentityConflict):
        choose_native('123', '1022', 'old@auth.local', profile, uid_rows)


def test_cfadmin_is_never_reused_by_employee_identity():
    with pytest.raises(IdentityConflict):
        choose_native('123', '1022', 'cfadmin@etech.com', ('cfadmin@etech.com', '123'), [])


@pytest.fixture
def callback_runtime(monkeypatch):
    # Stub only deployment I/O; exercise the callback itself so protocol wiring
    # errors cannot hide behind pure identity-selection tests.
    import sys
    import time
    from types import SimpleNamespace as NS
    from unittest.mock import Mock
    from cloudfile_ext.sso import eap_oauth
    import cloudfile_extensions.identity.oidc as oidc
    settings = NS(OAUTH_CLIENT_ID='client', OAUTH_CLIENT_SECRET='secret',
                  OAUTH_REDIRECT_URL='https://files.test/oauth/callback/',
                  OAUTH_TOKEN_URL='https://auth.test/token/',
                  OAUTH_USER_INFO_URL='https://auth.test/userinfo/',
                  CF_SSO_EAP_OIDC_ISSUER='https://auth.test/application/o/files/',
                  CF_SSO_EAP_OIDC_JWKS_URL='https://auth.test/jwks/',
                  OAUTH_PROVIDER='authentik:files', SITE_ROOT='/')
    token = {'access_token': 'access', 'id_token': 'signed'}
    info = {'sub': 'stable', 'userId': '123', 'preferred_username': '1022'}
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    client.fetch_token.return_value = token
    factory = Mock(return_value=client)
    auth = NS(login=Mock())
    response = Mock()
    redirect = Mock(return_value=response)
    error = Mock(return_value='refused')
    monkeypatch.setitem(sys.modules, 'django.conf', NS(settings=settings))
    monkeypatch.setitem(sys.modules, 'django.http', NS(HttpResponseRedirect=redirect))
    rotate = Mock()
    monkeypatch.setitem(sys.modules, 'django.middleware.csrf', NS(rotate_token=rotate))
    monkeypatch.setitem(sys.modules, 'requests_oauthlib', NS(OAuth2Session=factory))
    monkeypatch.setitem(sys.modules, 'seahub.auth', auth)
    monkeypatch.setitem(sys.modules, 'seahub', NS(auth=auth))
    monkeypatch.setitem(sys.modules, 'seahub.api2.utils', NS(get_api_token=lambda request: NS(key='api')))
    monkeypatch.setitem(sys.modules, 'seahub.utils', NS(render_error=error))
    validator = Mock()
    validator.validate.return_value = {'userId': '123'}
    monkeypatch.setattr(oidc, 'IDTokenValidator', Mock(return_value=validator))
    monkeypatch.setattr(oidc, 'SigningKeys', Mock())
    monkeypatch.setattr(eap_oauth.JsonClient, 'get', Mock(return_value=info))
    provision = Mock(return_value=NS(username='old@auth.local'))
    monkeypatch.setattr(eap_oauth, 'provision', provision)
    prepare = Mock()
    monkeypatch.setattr(eap_oauth, 'prepare_login_subject', prepare)
    request = NS(GET={'code': 'code', 'state': 'state'}, session={
        'cf_eap_oidc': dict(state='state', nonce='nonce', verifier='verifier', issued=time.time()),
        'oauth_redirect': '/library/'})
    return NS(request=request, client=client, auth=auth, validator=validator,
              provision=provision, redirect=redirect, response=response, info=info, rotate=rotate, prepare=prepare)


def test_callback_consumes_flow_checks_token_then_provisions(callback_runtime):
    from cloudfile_ext.sso.eap_oauth import callback
    r = callback_runtime
    assert callback(r.request) is r.response
    assert 'cf_eap_oidc' not in r.request.session
    assert r.client.fetch_token.call_args.kwargs['code_verifier'] == 'verifier'
    assert r.client.fetch_token.call_args.kwargs['allow_redirects'] is False
    assert r.validator.validate.call_args.kwargs['nonce'] == 'nonce'
    r.provision.assert_called_once_with('authentik:files', r.info)
    r.prepare.assert_called_once_with('123', 'old@auth.local')
    r.auth.login.assert_called_once()
    r.rotate.assert_called_once_with(r.request)
    r.redirect.assert_called_once_with('/library/')
    # A consumed flow cannot be replayed even with the same browser session.
    assert callback(r.request) == 'refused'
    assert r.auth.login.call_count == 1
    assert r.rotate.call_count == 1


@pytest.mark.parametrize('failure', ['state', 'expired', 'signature', 'uid', 'directory', 'projection'])
def test_callback_never_logs_in_on_protocol_or_identity_failure(callback_runtime, failure):
    from cloudfile_ext.sso.eap_oauth import callback
    r = callback_runtime
    if failure == 'state':
        r.request.GET['state'] = 'wrong'
    elif failure == 'expired':
        r.request.session['cf_eap_oidc']['issued'] -= 301
    elif failure == 'signature':
        r.validator.validate.side_effect = ValueError('invalid signature')
    elif failure == 'uid':
        r.info['userId'] = '456'
    elif failure == 'directory':
        r.provision.side_effect = IdentityConflict('directory unavailable')
    else:
        r.prepare.side_effect = IdentityConflict('projection unavailable')
    assert callback(r.request) == 'refused'
    r.auth.login.assert_not_called()
    r.rotate.assert_not_called()
    assert 'cf_eap_oidc' not in r.request.session


def test_jwks_http_https_and_invalid_urls():
    from cloudfile_extensions.identity.oidc import SigningKeys
    from cloudfile_ext.sso.eap_oauth import JsonClient
    url = 'http://dev.test/ssoauth/jwks/'
    assert SigningKeys(url, client=JsonClient()).url == url
    assert SigningKeys(url, client=JsonClient(), allow_http=True).url == url
    assert SigningKeys(url, allow_http=True).url == url
    for unsafe in ['http://user:pass@dev.test/jwks/', 'http://dev.test/jwks/?x=1',
                   'http://dev.test/jwks/#fragment', 'http:///jwks/']:
        with pytest.raises(ValueError):
            SigningKeys(unsafe, client=JsonClient(), allow_http=True)


def test_dev_http_keys_still_enforce_signed_identity():
    import json
    import time
    import jwt
    from types import SimpleNamespace
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cloudfile_extensions.identity.oidc import SigningKeys, IDTokenValidator
    from cloudfile_extensions.common.errors import ContractError
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = dict(json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())), kid='key-1')
    client = SimpleNamespace(get=lambda *args, **kwargs: {'keys': [public]})
    validator = IDTokenValidator(SimpleNamespace(issuer='http://dev.test/idp/', client_id='files',
        user_id_claim='userId'), SigningKeys('http://dev.test/jwks/', client=client, allow_http=True))
    claims = dict(iss='http://dev.test/idp/', aud='files', sub='stable', userId='123',
                  iat=int(time.time()), exp=int(time.time()) + 60, nonce='one-use')
    def validate(payload, key=private):
        token = jwt.encode(payload, key, algorithm='RS256', headers={'kid': 'key-1'})
        return validator.validate(token, nonce='one-use', access_token='access',
                                  userinfo={'sub': 'stable', 'userId': '123'})
    assert validate(claims)['userId'] == '123'
    for field, value in [('iss', 'http://other.test/'), ('aud', 'other'), ('nonce', 'wrong'),
                         ('userId', '456'), ('exp', int(time.time()) - 120)]:
        with pytest.raises(ContractError):
            validate(dict(claims, **{field: value}))
    with pytest.raises(ContractError):
        validate(claims, rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.mark.parametrize('failure', [None, 'issuer', 'directory'])
def test_legacy_callback_uses_owned_directory_and_closes_client(monkeypatch, failure):
    import sys
    from contextlib import nullcontext
    from types import SimpleNamespace as NS
    from unittest.mock import Mock
    from cloudfile_extensions.identity.resources import LoginResources
    from cloudfile_extensions.directory.provider import DirectoryProvider
    from cloudfile_ext.sso.eap_oauth import identity_context
    source = Mock(spec=DirectoryProvider)
    source.client = Mock()
    source.fetch.return_value = {'user_id': '123', 'status': 'active'}
    resources = Mock(spec=LoginResources)
    resources.oidc = NS(issuer='https://idp.test/')
    resources.resources = NS(directory_factory=lambda: source)
    settings = NS(CLOUDFILE_OIDC_LOGIN_RESOURCE_SCOPE=lambda: nullcontext(resources),
                  CF_SSO_EAP_OIDC_ISSUER='https://other.test/' if failure == 'issuer' else 'https://idp.test/')
    monkeypatch.setitem(sys.modules, 'django.conf', NS(settings=settings))
    if failure == 'directory':
        source.fetch.side_effect = IdentityConflict('unavailable')
    if failure:
        with pytest.raises(IdentityConflict):
            identity_context('123')
    else:
        assert identity_context('123') == source.fetch.return_value
    if failure == 'issuer':
        source.fetch.assert_not_called()
    else:
        source.fetch.assert_called_once_with('123')
        source.client.session.close.assert_called_once()


@pytest.mark.parametrize('failure', [None, 'scope', 'issuer', 'binding', 'expired'])
def test_ttl_oauth_prepares_the_exact_native_subject_before_login(monkeypatch, failure):
    import sys
    from contextlib import nullcontext
    from types import SimpleNamespace as NS
    from unittest.mock import Mock
    from cloudfile_extensions.identity.resources import LoginResources
    from cloudfile_ext.sso.eap_oauth import prepare_login_subject
    preparation = Mock()
    preparation.state.username.return_value = 'other@auth.local' if failure == 'binding' else 'native@auth.local'
    preparation.prepare.return_value = {'context_epoch': 'a' * 32}
    preparation.contexts.current.return_value = None if failure == 'expired' else {'context_epoch': 'a' * 32}
    resources = Mock(spec=LoginResources)
    resources.oidc = NS(issuer='https://other.test/' if failure == 'issuer' else 'https://idp.test/')
    resources.resources = NS(preparation=lambda *args: nullcontext(preparation))
    settings = NS(CLOUDFILE_POLICY_CONFIG={'membership_mode': 'subject_ttl'},
                  CLOUDFILE_OIDC_LOGIN_RESOURCE_SCOPE=None if failure == 'scope' else lambda: nullcontext(resources),
                  CF_SSO_EAP_OIDC_ISSUER='https://idp.test/')
    monkeypatch.setitem(sys.modules, 'django.conf', NS(settings=settings))
    if failure:
        with pytest.raises(IdentityConflict):
            prepare_login_subject('123', 'native@auth.local')
    else:
        prepare_login_subject('123', 'native@auth.local')
        preparation.prepare.assert_called_once_with('123', trigger='login')
    if failure in ('scope', 'issuer', 'binding'):
        preparation.prepare.assert_not_called()
