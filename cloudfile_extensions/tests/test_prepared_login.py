"""Login orchestration fixtures; not IdP or browser-session verification."""
import unittest
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.preparation import SubjectPreparation
from cloudfile_extensions.identity.login import PreparedOIDCLogin
from cloudfile_extensions.identity.oidc import OIDCFlow
from cloudfile_extensions.identity.sql_bindings import SQLIdentityBindings


class PreparedLoginTest(unittest.TestCase):
    def setUp(self):
        self.flow = Mock(spec=OIDCFlow)
        self.flow.complete.return_value = (dict(issuer="https://idp.example.invalid/", sub="sub", userId="u1"), "/files/")
        self.bindings = Mock(spec=SQLIdentityBindings)
        self.bindings.resolve.return_value = "native@example.invalid"
        self.preparation = Mock(spec=SubjectPreparation)
        self.preparation.actor = "u1"
        self.preparation.prepare.return_value = dict(context_epoch="a" * 32)
        self.factory = Mock(return_value=self.preparation)
        self.login = PreparedOIDCLogin(self.flow, self.bindings, preparation_factory=self.factory)

    def complete(self):
        return self.login.complete(state="state", code="code", binding="browser")

    def test_oidc_then_resolve_prepare_login_recheck(self):
        value = self.complete()
        self.assertEqual((value.user_id, value.username, value.context_epoch, value.redirect),
                         ("u1", "native@example.invalid", "a" * 32, "/files/"))
        self.flow.complete.assert_called_once_with(state="state", code="code", binding="browser")
        self.factory.assert_called_once_with("u1")
        self.preparation.prepare.assert_called_once_with("u1", trigger="login")
        self.assertEqual(self.bindings.resolve.call_count, 2)

    def test_failed_authentication_never_prepares(self):
        self.flow.complete.side_effect = ContractError("AUTHENTICATION_REQUIRED", "Rejected", 401)
        with self.assertRaises(ContractError):
            self.complete()
        self.bindings.resolve.assert_not_called()
        self.factory.assert_not_called()

    def test_unbound_identity_does_not_create_or_merge(self):
        self.bindings.resolve.return_value = None
        with self.assertRaises(ContractError) as caught:
            self.complete()
        self.assertEqual(caught.exception.status, 409)
        self.factory.assert_not_called()

    def test_preparation_failure_or_late_unbind_cannot_return_login(self):
        self.preparation.prepare.side_effect = ContractError("SUBJECT_UNAVAILABLE", "Unavailable", 503)
        with self.assertRaises(ContractError):
            self.complete()
        self.preparation.prepare.side_effect = None
        self.bindings.resolve.side_effect = ["native@example.invalid", None]
        with self.assertRaises(ContractError):
            self.complete()

    def test_factory_cannot_prepare_another_actor(self):
        self.preparation.actor = "u2"
        with self.assertRaises(ContractError):
            self.complete()
        self.preparation.prepare.assert_not_called()
