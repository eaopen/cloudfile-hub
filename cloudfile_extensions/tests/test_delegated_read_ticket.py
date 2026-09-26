"""Real delegation JWT with mocked directory/native RPC; no release evidence."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import jwt

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.preparation import SubjectPreparation
from cloudfile_extensions.identity.delegated_read_ticket import DelegatedReadTicketIssuer
from cloudfile_extensions.identity.service_revocations import ServiceRevocations
from cloudfile_extensions.identity.user_delegation import DelegationKey, UserDelegationVerifier


class DelegatedReadTicketTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.redis = Mock()
        self.redis.get.return_value = None
        self.key = DelegationKey("login", "issuer", "download", "etech", b"fixture-signing-secret-32bytes-long")
        verifier = UserDelegationVerifier({"dedicated": self.key},
            revocations=ServiceRevocations(self.redis, clock=lambda: self.now), clock=lambda: self.now)
        self.preparation = Mock(spec=SubjectPreparation)
        self.preparation.actor = "user-1"
        self.preparation.state = Mock(provider="etech")
        self.preparation.state.username.return_value = "native-user"
        self.preparation.contexts = Mock()
        self.preparation.contexts.current.return_value = dict(context_epoch="a" * 32)
        self.issuer = DelegatedReadTicketIssuer(self.preparation, verifier)
        self.reference = dict(repo_id="11111111-1111-1111-1111-111111111111", path="/file", kind="file")
        claims = dict(iss="issuer", aud="download", sub="login", userId="user-1", provider="etech",
            iat=1000, exp=1060, jti="delegation-1", context_epoch="a" * 32,
            resource=self.reference, action="download")
        token = jwt.encode(claims, self.key.secret, algorithm="HS256",
            headers=dict(kid="dedicated", typ="cf-user-delegation+jwt"))
        self.request = SimpleNamespace(is_secure=lambda: True, GET={}, headers={"Authorization": "Bearer " + token})
        self.ticket = "22222222-2222-2222-2222-222222222222"

    def test_actual_verified_claims_attached_and_remaining_ttl_shortened(self):
        def native(*args):
            self.now = 1012.5
            return self.ticket
        with patch("cloudfile_extensions.identity.delegated_read_ticket.resolve_and_issue_native_ticket",
                side_effect=native) as rpc:
            result = self.issuer.issue(self.request, self.reference)
        self.assertEqual(result, dict(ticket=self.ticket, expires_in=47))
        args = rpc.call_args.args
        self.assertEqual(args[:4], (self.reference["repo_id"], "/file", "download", "native-user"))
        conditions = json.loads(args[4])
        self.assertNotIn("oidc_session", conditions)
        self.assertEqual(conditions["user_delegation"], dict(service_id="login", token_id="delegation-1",
            issued_at=1000, expires_at=1060))

    def test_mismatched_resource_or_epoch_prevents_native_issuance(self):
        with patch("cloudfile_extensions.identity.delegated_read_ticket.resolve_and_issue_native_ticket") as rpc:
            with self.assertRaises(ContractError):
                self.issuer.issue(self.request, dict(self.reference, path="/other"))
            self.preparation.contexts.current.return_value = dict(context_epoch="b" * 32)
            with self.assertRaises(ContractError):
                self.issuer.issue(self.request, self.reference)
            rpc.assert_not_called()

    def test_native_success_followed_by_revocation_never_delivers_ticket(self):
        def native(*args):
            self.redis.get.return_value = b"1"
            return self.ticket
        with patch("cloudfile_extensions.identity.delegated_read_ticket.resolve_and_issue_native_ticket",
                side_effect=native), self.assertRaises(ContractError):
            self.issuer.issue(self.request, self.reference)

    def test_native_success_followed_by_epoch_change_never_delivers_ticket(self):
        self.preparation.contexts.current.side_effect = [dict(context_epoch="a" * 32), dict(context_epoch="b" * 32)]
        with patch("cloudfile_extensions.identity.delegated_read_ticket.resolve_and_issue_native_ticket",
                return_value=self.ticket), self.assertRaises(ContractError):
            self.issuer.issue(self.request, self.reference)
