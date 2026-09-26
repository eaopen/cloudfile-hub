"""Actual machine/JWT crypto; mocked authority/audit are not SQL evidence."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import jwt

from cloudfile_extensions.authorization.read import ContentReadAuthority
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.delegation_issue import UserDelegationIssuer
from cloudfile_extensions.identity.service_revocations import ServiceRevocations
from cloudfile_extensions.identity.service_tokens import ServiceCredential, ServiceTokenVerifier
from cloudfile_extensions.identity.user_delegation import DelegationKey


class DelegationIssueTests(unittest.TestCase):
    def setUp(self):
        self.redis = Mock()
        self.redis.get.return_value = None
        self.machine_secret = b"fixture-machine-key-32bytes-or-longer"
        credential = ServiceCredential("login", "machine-issuer", "cf-issue", self.machine_secret,
            frozenset({"user.delegation.issue"}))
        self.verifier = ServiceTokenVerifier({"machine": credential}, clock=lambda: 1000,
            revocations=ServiceRevocations(self.redis, clock=lambda: 1000))
        self.key = DelegationKey("login", "delegation-issuer", "cf-download", "etech",
            b"fixture-dedicated-delegation-key-long")
        self.authority = object.__new__(ContentReadAuthority)
        self.authority.actor = "business-user"
        self.authority.state = SimpleNamespace(provider="etech")
        self.authority.rules = SimpleNamespace(request_id="request-fixture")
        self.authority.preparation = Mock()
        self.authority.preparation.contexts.current.return_value = dict(context_epoch="a" * 32)
        self.cursor = Mock()
        def consume(reference, reader):
            self.authority.epoch = "a" * 32
            return reader(self.cursor, reference)
        self.authority.consume = Mock(side_effect=consume)
        self.issuer = UserDelegationIssuer(authority=self.authority, service_verifier=self.verifier,
            signing_key=self.key, kid="dedicated")
        token = jwt.encode(dict(iss="machine-issuer", aud="cf-issue", sub="login",
            iat=1000, exp=1020, jti="machine-token", scope="user.delegation.issue"),
            self.machine_secret, algorithm="HS256", headers=dict(kid="machine", typ="JWT"))
        self.request = SimpleNamespace(is_secure=lambda: True, GET={}, headers={"Authorization": "Bearer " + token})
        self.reference = dict(repo_id="11111111-1111-1111-1111-111111111111", path="/file", kind="file")

    def test_signs_actual_subject_epoch_and_audits_service_without_token(self):
        with patch("cloudfile_extensions.identity.delegation_issue.EventWriter") as writer:
            response = self.issuer.issue(self.request, self.reference)
        claims = jwt.decode(response["delegation"], self.key.secret, algorithms=["HS256"],
            audience="cf-download", options={"verify_exp": False, "verify_iat": False})
        self.assertEqual((claims["userId"], claims["context_epoch"]), ("business-user", "a" * 32))
        self.assertEqual(response["expires_in"], 20)
        self.assertEqual(self.authority.consume.call_count, 2)
        event = writer.return_value.append.call_args.args[1]
        self.assertEqual((event["actor_user_id"], event["actor_kind"], event["target_user_id"]),
            ("login", "service", "business-user"))
        self.assertFalse({"token", "delegation", "jti", "secret"} & set(event))

    def test_audit_failure_never_returns_credential(self):
        with patch("cloudfile_extensions.identity.delegation_issue.EventWriter") as writer:
            writer.return_value.append.side_effect = RuntimeError("fixture audit failure")
            with self.assertRaises(RuntimeError):
                self.issuer.issue(self.request, self.reference)

    def test_epoch_change_prevents_signing_and_audit(self):
        self.authority.preparation.contexts.current.return_value = dict(context_epoch="b" * 32)
        with patch("cloudfile_extensions.identity.delegation_issue.EventWriter") as writer:
            with self.assertRaises(ContractError):
                self.issuer.issue(self.request, self.reference)
            writer.assert_not_called()

    def test_machine_key_cannot_sign_user_delegation(self):
        key = DelegationKey("login", "issuer", "audience", "etech", self.machine_secret)
        with self.assertRaises(ValueError):
            UserDelegationIssuer(authority=self.authority, service_verifier=self.verifier,
                signing_key=key, kid="dedicated")
