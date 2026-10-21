"""Real RSA protocol signatures; not provider/session index integration proof."""
import json
import unittest
from unittest.mock import Mock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.oidc import OIDCConfig, SigningKeys
from cloudfile_extensions.identity.logout_token import EVENT, LogoutTokenValidator


class LogoutTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.config = OIDCConfig("https://idp.invalid/", "cloudfile", "fixture-secret",
            "https://files.invalid/callback/", "https://idp.invalid/authorize/",
            "https://idp.invalid/token/", "https://idp.invalid/userinfo/", "https://idp.invalid/jwks/")
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private.public_key()))
        self.client = Mock()
        self.client.get.return_value = {"keys": [{**public, "kid": "key-1", "alg": "RS256"}]}
        self.keys = SigningKeys(self.config.jwks_url, client=self.client)
        self.validator = LogoutTokenValidator(self.config, self.keys, clock=lambda: 1000)
        self.claims = dict(iss=self.config.issuer, aud="cloudfile", iat=1000, exp=1060,
            jti="logout-1", sub="subject-1", sid="session-1", events={EVENT: {}})

    def token(self, changes=None, headers=None):
        return jwt.encode({**self.claims, **(changes or {})}, self.private, algorithm="RS256",
            headers={"kid": "key-1", **(headers or {})})

    def test_verified_notification_contains_no_raw_token(self):
        token = self.token()
        value = self.validator.validate(token)
        self.assertEqual((value.subject, value.session_id, value.jti), ("subject-1", "session-1", "logout-1"))
        self.assertNotIn(token, repr(value))

    def test_cross_jwt_and_claim_boundaries(self):
        for changes in ({"iss": "https://other.invalid/"}, {"aud": "other"},
                {"nonce": "login-nonce"}, {"events": {}}, {"events": {EVENT: True}},
                {"iat": True}, {"exp": 1000}, {"iat": 1031, "exp": 1090},
                {"sub": None, "sid": None}, {"jti": ""}, {"exp": 1400}):
            with self.subTest(changes=changes), self.assertRaises(ContractError) as caught:
                self.validator.validate(self.token(changes))
            self.assertEqual(caught.exception.status, 401)

    def test_untrusted_key_headers_rejected_before_jwks(self):
        with self.assertRaises(ContractError):
            self.validator.validate(self.token(headers={"jku": "https://untrusted.invalid/jwks"}))
        self.client.get.assert_not_called()

    def test_jwks_service_failure_preserved(self):
        self.client.get.side_effect = ContractError("UPSTREAM_UNAVAILABLE", "Unavailable", 503)
        with self.assertRaises(ContractError) as caught:
            self.validator.validate(self.token())
        self.assertEqual(caught.exception.status, 503)
