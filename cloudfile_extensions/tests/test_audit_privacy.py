"""Default audit privacy regressions; no native authorization fixture."""
import unittest

from cloudfile_extensions.events.privacy import default_redact


class AuditPrivacyTests(unittest.TestCase):
    def test_business_identity_without_native_operator(self):
        event = dict(schema_version=1, actor_user_id="employee-42", actor_kind="user",
                     operator="native@example.org", delegator="admin@example.org", id=7)
        result = default_redact("viewer", event)
        self.assertEqual(result["operator"], "employee-42")
        self.assertIsNone(result["delegator"])
        self.assertEqual(result["id"], 7)
        self.assertEqual(event["operator"], "native@example.org")

    def test_legacy_identity_is_not_inferred(self):
        result = default_redact("viewer", dict(schema_version=0, actor_user_id=None,
            actor_kind=None, operator="native@example.org", delegator=None))
        self.assertEqual(result["operator"], "[redacted]")
        self.assertIsNone(result["actor_user_id"])

    def test_invalid_or_guessed_identity_is_rejected(self):
        for event in (dict(schema_version=0, actor_user_id="guessed", actor_kind="user"),
                      dict(schema_version=1, actor_user_id="", actor_kind="user"),
                      dict(schema_version=True), dict(schema_version=2)):
            with self.assertRaises(Exception):
                default_redact("viewer", event)
