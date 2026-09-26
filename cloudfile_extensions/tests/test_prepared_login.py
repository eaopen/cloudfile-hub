"""Login orchestration fixtures; not IdP or browser-session verification."""
import unittest
import time
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.preparation import SubjectPreparation
from cloudfile_extensions.identity.login import PreparedOIDCLogin
from cloudfile_extensions.identity.oidc import OIDCFlow
from cloudfile_extensions.identity.sql_bindings import SQLIdentityBindings


class PreparedLoginTest(unittest.TestCase):
    def setUp(self):
        self.flow = Mock(spec=OIDCFlow)
        self.flow.complete.return_value = (dict(issuer="https://idp.example.invalid/", sub="sub", userId="u1", expires_at=int(time.time()) + 600), "/files/")
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

    def test_configured_jit_then_prepare_and_late_expiry(self):
        from cloudfile_extensions.identity.jit import SQLJITProvisioner
        jit = Mock(spec=SQLJITProvisioner)
        jit.bindings = self.bindings
        jit.ensure.return_value = "native@example.invalid"
        self.bindings.resolve.side_effect = [None, "native@example.invalid"]
        login = PreparedOIDCLogin(self.flow, self.bindings, preparation_factory=self.factory, jit=jit)
        self.assertEqual(login.complete(state="state", code="code", binding="browser").username, "native@example.invalid")
        jit.ensure.assert_called_once_with(self.flow.complete.return_value[0])
        self.bindings.resolve.side_effect = None
        def expire(*args, **kwargs):
            self.flow.complete.return_value[0]["expires_at"] = 1
            return dict(context_epoch="a" * 32)
        self.preparation.prepare.side_effect = expire
        with self.assertRaises(ContractError) as caught:
            self.complete()
        self.assertEqual(caught.exception.status, 401)

    def test_durable_provisioning_returns_pending_even_if_identity_exists(self):
        from cloudfile_extensions.identity.provisioning import ProvisioningJobs
        from cloudfile_extensions.identity.login import PendingLogin
        provisioning = Mock(spec=ProvisioningJobs)
        provisioning.jit = Mock()
        provisioning.jit.bindings = self.bindings
        provisioning.request_for_login.return_value = "job-id"
        login = PreparedOIDCLogin(self.flow, self.bindings, preparation_factory=self.factory, provisioning=provisioning)
        for username in (None, "native@example.invalid"):
            self.bindings.resolve.return_value = username
            result = login.complete(state="state", code="code", binding="browser")
            self.assertEqual(result, PendingLogin("job-id"))
            self.assertEqual(provisioning.request_for_login.call_args.kwargs["unbound"], username is None)
        self.factory.assert_not_called()
        provisioning.request_for_login.return_value = None
        self.assertEqual(login.complete(state="state", code="code", binding="browser").username, "native@example.invalid")
