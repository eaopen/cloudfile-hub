"""Own-context presentation contracts; mocks are not SQL/Redis proof."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from cloudfile_extensions.authorization.runtime import AuthenticatedPolicyActor
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.preparation import SubjectPreparation
from cloudfile_extensions.directory.self_context import OwnContextService


class OwnContextTests(unittest.TestCase):
    def setUp(self):
        self.preparation = Mock(spec=SubjectPreparation)
        self.preparation.actor = "employee"
        self.preparation.state = Mock()
        self.preparation.state.provider = "etech"
        self.preparation.state.username.return_value = "native@example.org"
        self.preparation.state.account_active.return_value = True
        self.preparation.state.barrier_active.return_value = False
        self.preparation.contexts = Mock()
        self.value = dict(userId="employee", status="ready", context_epoch="epoch-1",
            fetched_at=1000, expires_at=2000, subject=dict(private="not returned"))
        self.preparation.prepare.return_value = self.value
        self.preparation.contexts.current.return_value = self.value
        self.service = OwnContextService(self.preparation,
            AuthenticatedPolicyActor("employee", "native@example.org"))

    def test_fixed_public_fields_and_normal_trigger(self):
        result = self.service.get()
        self.assertEqual(set(result), {"userId", "status", "context_epoch", "fetched_at", "expires_at"})
        self.preparation.prepare.assert_called_once_with("employee", trigger="request")
        self.assertNotIn("private", str(result))

    def test_changed_epoch_or_binding_is_not_reported_ready(self):
        self.preparation.contexts.current.return_value = {**self.value, "context_epoch": "epoch-2"}
        with self.assertRaises(ContractError):
            self.service.get()
        self.preparation.contexts.current.return_value = self.value
        self.preparation.state.username.return_value = "other@example.org"
        with self.assertRaises(ContractError):
            self.service.get()

    def test_barrier_blocks_diagnostic_ready(self):
        self.preparation.state.barrier_active.return_value = True
        with self.assertRaises(ContractError):
            self.service.get()
