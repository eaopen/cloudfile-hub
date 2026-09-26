"""Actual JWT signature checks with fixture Redis, not native end-to-end proof."""
import unittest
from unittest.mock import Mock

import jwt

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.service_revocations import ServiceRevocations
from cloudfile_extensions.identity.user_delegation import DelegationKey, UserDelegationVerifier


class UserDelegationTests(unittest.TestCase):
    def setUp(self):
        self.redis = Mock()
        self.redis.get.return_value = None
        self.redis.eval.return_value = 1
        self.secret = b"fixture-only-delegation-secret-32bytes"
        self.key = DelegationKey("login-service", "issuer", "cf-download", "etech", self.secret)
        self.verifier = UserDelegationVerifier({"delegation-1": self.key},
            revocations=ServiceRevocations(self.redis, clock=lambda: 1000), clock=lambda: 1000)
        self.resource = dict(repo_id="11111111-1111-1111-1111-111111111111", path="/file", kind="file")
        self.claims = dict(iss="issuer", aud="cf-download", sub="login-service", iat=1000,
            exp=1060, jti="token-1", userId="employee-user-id", provider="etech",
            context_epoch="a" * 32, resource=self.resource, action="download")

    def token(self, claims=None, *, typ="cf-user-delegation+jwt", secret=None):
        return "Bearer " + jwt.encode(self.claims if claims is None else claims,
            self.secret if secret is None else secret, algorithm="HS256",
            headers=dict(kid="delegation-1", typ=typ))

    def test_exact_resource_action_and_immutable_resource(self):
        principal = self.verifier.verify(self.token())
        principal.require(self.resource, "download")
        with self.assertRaises(ContractError):
            principal.require(dict(self.resource, path="/other"), "download")
        with self.assertRaises(ContractError):
            principal.require(self.resource, "view")
        with self.assertRaises(TypeError):
            principal.resource["path"] = "/other"

    def test_machine_typ_and_wrong_signature_rejected(self):
        for token in (self.token(typ="JWT"), self.token(secret=b"other-fixture-secret-32bytes-long")):
            with self.subTest(token_type=token[:7]), self.assertRaises(ContractError):
                self.verifier.verify(token)
        self.redis.get.assert_not_called()

    def test_scope_lifetime_and_claim_boundaries(self):
        for changes in (dict(exp=1061), dict(exp=1000), dict(iat=True), dict(iat=1031, exp=1060),
                dict(provider="other"), dict(aud="refresh"), dict(sub="other-service"),
                dict(userId=123), dict(context_epoch="A" * 32), dict(action="upload"),
                dict(resource=dict(self.resource, kind="dir")), dict(nbf=1000)):
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                self.verifier.verify(self.token(dict(self.claims, **changes)))

    def test_revoked_corrupt_and_unavailable_store_fail_closed(self):
        for value in (b"1", b"corrupt"):
            self.redis.get.return_value = value
            with self.subTest(value=value), self.assertRaises(ContractError):
                self.verifier.verify(self.token())
        self.redis.get.side_effect = RuntimeError("fixture Redis unavailable")
        with self.assertRaises(ContractError) as error:
            self.verifier.verify(self.token())
        self.assertEqual(error.exception.status, 503)

    def test_trusted_revoke_uses_actual_bounded_marker(self):
        principal = self.verifier.verify(self.token())
        self.assertTrue(self.verifier.revoke(principal))
        arguments = self.redis.eval.call_args.args
        self.assertEqual(arguments[-1], 361)
        self.assertTrue(arguments[-2].startswith("cf:service-revocations:"))
        with self.assertRaises(ValueError):
            self.verifier.revoke(dict(token_id="token-1"))

    def test_expired_verified_delegation_can_revoke_existing_transfer(self):
        principal = self.verifier.verify(self.token())
        self.now = principal.expires_at + 10
        self.assertTrue(self.verifier.revoke(principal))
        self.assertEqual(self.redis.eval.call_args.args[-1], 291)
