"""CloudFile outbound v2 machine JWT contract; no Django or real network required."""
import base64
import hashlib
import importlib
import hmac
import json
import sys
import types

import pytest

@pytest.fixture
def service_module(monkeypatch):
    # Keep this unit suite Django-free, like the existing SSO tests.
    conf = types.ModuleType('django.conf')
    conf.settings = types.SimpleNamespace()
    django = types.ModuleType('django')
    django.conf = conf
    monkeypatch.setitem(sys.modules, 'django', django)
    monkeypatch.setitem(sys.modules, 'django.conf', conf)
    monkeypatch.delitem(sys.modules, 'cloudfile_ext.external_service', raising=False)
    return importlib.import_module('cloudfile_ext.external_service')


SECRET = 'test-only-directory-secret-at-least-32bytes'


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _jwt_encode(payload, secret, algorithm, headers=None):
    assert algorithm == 'HS256'
    hdr = {'alg': algorithm, 'typ': 'JWT'}
    hdr.update(headers or {})
    head = _b64(json.dumps(hdr).encode('utf-8'))
    body = _b64(json.dumps(payload).encode('utf-8'))
    signed = (head + '.' + body).encode('ascii')
    sig = _b64(hmac.new(secret.encode('utf-8'), signed, hashlib.sha256).digest())
    return signed.decode('ascii') + '.' + sig


def _decode(token):
    header, payload, _ = token.split('.')
    def unpack(s):
        return json.loads(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))
    return unpack(header), unpack(payload)


def test_v2_jwt_matches_eap_service_verifier_contract(monkeypatch, service_module):
    monkeypatch.setitem(sys.modules, 'jwt', types.SimpleNamespace(encode=_jwt_encode))
    client = service_module.ExternalService('SSO_DIRECTORY', 'http://eap.example.invalid/admin-api/eap/cloudDrive/directory',
                             secret=SECRET, auth_mode='v2', key_id='cf-key-1')
    auth = client._headers()['Authorization']
    assert auth.startswith('Bearer ')
    header, payload = _decode(auth[7:])
    assert header == {'alg': 'HS256', 'typ': 'JWT', 'kid': 'cf-key-1'}
    assert payload['iss'] == 'cloudfile-sso'
    assert payload['aud'] == 'eap-directory'
    assert payload['sub'] == 'cloudfile'
    assert payload['scope'] == 'directory.read'
    assert payload['jti']
    assert payload['exp'] - payload['iat'] == 300
    assert client._headers()['Authorization'] != auth  # jti changes


@pytest.mark.parametrize('key_id,secret', [('', SECRET), ('k1', 'short')])
def test_v2_refuses_missing_or_weak_credentials(key_id, secret, service_module):
    client = service_module.ExternalService('SSO_DIRECTORY', 'http://example.invalid',
                             secret=secret, auth_mode='v2', key_id=key_id)
    with pytest.raises(service_module.ExternalServiceError):
        client._headers()


def test_old_outbound_scheme_remains_explicit_legacy(monkeypatch, service_module):
    monkeypatch.setitem(sys.modules, 'jwt', types.SimpleNamespace(encode=_jwt_encode))
    client = service_module.ExternalService('OTHER', 'http://example.invalid', secret=SECRET)
    auth = client._headers()['Authorization']
    assert auth.startswith('Token ')
    head, claims = _decode(auth[6:])
    assert 'kid' not in head and 'scope' not in claims


def test_unsupported_auth_mode_is_rejected(service_module):
    with pytest.raises(ValueError):
        service_module.ExternalService('SSO_DIRECTORY', 'http://example.invalid', auth_mode='unknown')
