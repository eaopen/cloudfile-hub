"""Machine protocol regressions; mock Redis does not prove runtime durability."""
import unittest
from unittest.mock import Mock
import jwt

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.service_tokens import ServiceCredential, ServiceTokenVerifier
from cloudfile_extensions.identity.service_revocations import ServiceRevocations


class ServiceRevocationTests(unittest.TestCase):
    def setUp(self):
        self.redis = Mock()
        self.redis.get.return_value = None
        self.redis.eval.return_value = 1
        self.now = 1000
        self.secret = b"test-only-fixed-secret-with-at-least-32-bytes"
        self.credential = ServiceCredential("etech", "issuer", "cloudfile", self.secret,
            frozenset({"authorization.refresh.user"}))
        self.revocations = ServiceRevocations(self.redis, clock=lambda: self.now)
        self.verifier = ServiceTokenVerifier({"key": self.credential}, clock=lambda: self.now,
            revocations=self.revocations)

    def token(self, *, changes=None, headers=None):
        claims = dict(iss="issuer", aud="cloudfile", sub="etech", iat=1000, exp=1060,
            jti="token-1", scope="authorization.refresh.user")
        claims.update(changes or {})
        return "Bearer " + jwt.encode(claims, self.secret, algorithm="HS256",
            headers={"kid": "key", **(headers or {})})

    def test_verified_principal_and_transaction_recheck(self):
        principal = self.verifier.verify(self.token())
        self.assertEqual(principal.service_id, "etech")
        self.redis.get.return_value = b"1"
        with self.assertRaises(ContractError) as caught:
            self.verifier.assert_active(principal)
        self.assertEqual(caught.exception.status, 401)

    def test_revocation_failure_is_not_signature_only_fallback(self):
        self.redis.get.side_effect = RuntimeError("private redis settings")
        with self.assertRaises(ContractError) as caught:
            self.verifier.verify(self.token())
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("private", caught.exception.message)

    def test_multi_audience_and_unimplemented_headers_are_rejected(self):
        for token in (self.token(changes={"aud": ["cloudfile", "other"]}),
                      self.token(headers={"crit": ["unknown"]}),
                      self.token(headers={"jku": "https://untrusted.invalid/keys"})):
            with self.assertRaises(ContractError):
                self.verifier.verify(token)

    def test_revocation_uses_only_verified_identity_and_bounded_ttl(self):
        principal = self.verifier.verify(self.token())
        self.assertTrue(self.revocations.revoke(principal))
        args = self.redis.eval.call_args.args
        self.assertEqual(args[1], 1)
        self.assertTrue(args[2].startswith("cf:service-revocations:"))
        self.assertEqual(args[3], 61)
        self.assertNotIn("token-1", args[2])

    def test_invalid_scope_configuration_is_rejected(self):
        for scope in ("auth\x00scope", "auth\tscope", "x" * 129):
            with self.assertRaises(ValueError):
                ServiceCredential("etech", "issuer", "cloudfile", self.secret, frozenset({scope}))
