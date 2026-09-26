"""Native adapter boundary tests; RPC/ORM objects here are isolated fixtures."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.accounts import NativeAccounts


class NativeAccountTests(TestCase):
    def setUp(self):
        self.profiles = SimpleNamespace(objects=Mock(),
            DoesNotExist=type("MissingProfile", (Exception,), {}),
            MultipleObjectsReturned=type("DuplicateProfile", (Exception,), {}))
        self.users = SimpleNamespace(objects=Mock(), DoesNotExist=type("MissingAccount", (Exception,), {}))
        self.account = SimpleNamespace(username="native@example.invalid", is_active=True)
        self.users.objects.get.return_value = self.account
        self.profiles.objects.get.return_value = SimpleNamespace(
            user=self.account.username, login_id="business-1")
        self.adapter = NativeAccounts(profiles=self.profiles, users=self.users)

    def test_exact_mapping_only_without_alias_fallback_or_writes(self):
        self.assertIs(self.adapter.by_user_id("business-1"), self.account)
        self.profiles.objects.get.assert_called_once_with(login_id="business-1")
        self.users.objects.get.assert_called_once_with(email=self.account.username)
        self.assertTrue(self.adapter.active_user_id("business-1"))
        self.assertFalse(self.profiles.objects.create.called)

    def test_missing_identity_returns_false_but_rpc_errors_never_allow(self):
        self.profiles.objects.get.side_effect = self.profiles.DoesNotExist()
        self.assertFalse(self.adapter.active_user_id("business-1"))
        self.users.objects.get.side_effect = RuntimeError("private RPC configuration")
        with self.assertRaises(ContractError) as caught:
            self.adapter.active_username("native@example.invalid")
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("private", caught.exception.message)

    def test_collation_mismatch_does_not_resolve_another_identity(self):
        with self.assertRaises(ContractError) as caught:
            self.adapter.by_user_id("BUSINESS-1")
        self.assertEqual(caught.exception.status, 409)
        self.users.objects.get.assert_not_called()
        self.account.username = "another@example.invalid"
        with self.assertRaises(ContractError):
            self.adapter.by_username("native@example.invalid")

    def test_disabled_missing_or_malformed_account_is_never_active(self):
        for status in (False, 0, "1", "true", 2, None):
            self.account.is_active = status
            self.assertFalse(self.adapter.active_username(self.account.username))
        self.users.objects.get.side_effect = self.users.DoesNotExist()
        self.assertFalse(self.adapter.active_username(self.account.username))

    def test_ambiguous_mapping_and_database_failure_never_lookup_account(self):
        for failure, status in ((self.profiles.MultipleObjectsReturned("private rows"), 409),
                                (RuntimeError("private database configuration"), 503)):
            self.profiles.objects.get.side_effect = failure
            with self.assertRaises(ContractError) as caught:
                self.adapter.active_user_id("business-1")
            self.assertEqual(caught.exception.status, status)
            self.assertNotIn("private", caught.exception.message)
            self.users.objects.get.assert_not_called()
