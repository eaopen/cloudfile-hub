"""Signed-token success and rejection tests, without a second identity system."""
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

from cloudfile_ext.v2.errors import IdentityUnavailable
from cloudfile_ext.v2.oidc import configuration, verify_id_token


class OIDCTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def verify(self, changes=None, *, signing_key=None, nonce='nonce'):
        now = int(time.time())
        claims = {'iss': 'https://idp.example.test/files/', 'sub': 'trusted-sub',
                  'aud': 'client', 'iat': now, 'exp': now + 60, 'nonce': 'nonce'}
        claims.update(changes or {})
        raw = jwt.encode(claims, signing_key or self.key, algorithm='RS256', headers={'kid': 'one'})
        client = Mock()
        client.get_signing_key_from_jwt.return_value = SimpleNamespace(key=self.key.public_key())
        with patch('cloudfile_ext.v2.oidc.key_client', return_value=client):
            return verify_id_token({'id_token': raw, 'access_token': 'access'},
                                   issuer='https://idp.example.test/files/', client_id='client', nonce=nonce,
                                   jwks_uri='https://idp.example.test/jwks/')

    def test_valid_signed_identity(self):
        self.assertEqual(self.verify()['sub'], 'trusted-sub')

    def test_wrong_issuer_audience_expiry_nonce_subject_and_hash_are_rejected(self):
        for claims in ({'iss': 'https://other.example.test/'}, {'aud': 'other'}, {'exp': 1},
                       {'nonce': 'other'}, {'sub': ''}, {'at_hash': 'other'},
                       {'aud': ['client', 'other']}, {'azp': 'other'}):
            with self.subTest(claims=claims), self.assertRaises(IdentityUnavailable):
                self.verify(claims)
        with self.assertRaises(IdentityUnavailable):
            self.verify(nonce=None)

    def test_untrusted_signature_is_rejected(self):
        with self.assertRaises(IdentityUnavailable):
            self.verify(signing_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))

    def test_missing_id_token_and_missing_required_claim_are_rejected(self):
        with self.assertRaises(IdentityUnavailable):
            verify_id_token({}, issuer='issuer', client_id='client', nonce='nonce', jwks_uri='https://idp.example.test/jwks/')
        with self.assertRaises(IdentityUnavailable):
            self.verify({'nonce': None})

    def test_configuration_requires_trusted_endpoints(self):
        settings = SimpleNamespace(OAUTH_OIDC_ISSUER='https://idp.example.test/files/',
                                   OAUTH_OIDC_JWKS_URI='https://idp.example.test/jwks/')
        self.assertEqual(configuration(settings)[0], settings.OAUTH_OIDC_ISSUER)
        for uri in ('', 'file:///etc/passwd', 'http://idp.example.test/jwks/', 'https://user:pass@idp.example.test/jwks/'):
            settings.OAUTH_OIDC_JWKS_URI = uri
            with self.assertRaises(IdentityUnavailable):
                configuration(settings)
