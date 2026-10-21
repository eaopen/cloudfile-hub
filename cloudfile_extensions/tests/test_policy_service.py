"""Service contract fixtures, not host authentication or native guard evidence."""
import unittest
from unittest.mock import Mock
from uuid import uuid4

from cloudfile_extensions.authorization.management import DirectoryManagement
from cloudfile_extensions.authorization.rules import rule_value
from cloudfile_extensions.authorization.service import DirectoryPolicyService
from cloudfile_extensions.common.errors import ContractError


class PolicyServiceTest(unittest.TestCase):
    def setUp(self):
        self.management = object.__new__(DirectoryManagement)
        self.management.rules = Mock(validate=rule_value)
        self.management.mutate = Mock(return_value={"fixture": True})
        self.management.list_target = Mock(return_value={"items": [], "next_after": None})
        self.service = DirectoryPolicyService(self.management)
        self.ref = dict(repo_id=str(uuid4()), path="/parts", kind="dir")
        self.value = dict(path="/parts", kind="dir", permission="r", inherit=False,
            subject=dict(type="user", provider="directory", namespace="user", external_id="u1"))
        self.request = dict(reference=self.ref, value=self.value)

    def test_domain_dispatch_and_trusted_actor_not_in_body(self):
        self.service.create("acl", self.request, idempotency_key="one")
        self.management.mutate.assert_called_once_with(self.ref, value=self.value,
            rule_id=None, if_match=None, idempotency_key="one")
        with self.assertRaises(ContractError):
            self.service.create("admins", self.request, idempotency_key="two")
        with self.assertRaises(ContractError):
            self.service.create("acl", {**self.request, "actor": "other"}, idempotency_key="three")

    def test_required_idempotency_and_strong_condition(self):
        with self.assertRaises(ContractError) as caught:
            self.service.create("acl", self.request, idempotency_key=None)
        self.assertEqual(caught.exception.code, "IDEMPOTENCY_REQUIRED")
        for condition, status in ((None, 428), ("*", 400), ('W/"old"', 400)):
            with self.assertRaises(ContractError) as caught:
                self.service.replace("acl", str(uuid4()), self.request, if_match=condition, idempotency_key="replace")
            self.assertEqual(caught.exception.status, status)
        self.management.mutate.assert_not_called()

    def test_deletion_body_and_directory_only_delegation(self):
        with self.assertRaises(ContractError):
            self.service.delete("acl", str(uuid4()), self.request, if_match='"old"', idempotency_key="delete")
        with self.assertRaises(ContractError):
            self.service.list("admins", dict(reference={**self.ref, "kind": "file"}))
        self.service.list("acl", dict(reference=self.ref), limit=10, after=None)
        self.management.list_target.assert_called_once_with(self.ref, limit=10, after=None)
