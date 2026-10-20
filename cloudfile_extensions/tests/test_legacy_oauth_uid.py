"""Focused, pure legacy OAuth UID selection and compatibility tests."""
import unittest

from cloudfile_extensions.identity.legacy_oauth import (
    UIDBindingError, choose_uid_owner, trusted_uid_mapping)


class LegacyUIDSelectionTests(unittest.TestCase):
    def test_only_explicit_user_id_claim_changes_legacy_account_resolution(self):
        self.assertTrue(trusted_uid_mapping({"userId": (True, "login_id")}))
        self.assertTrue(trusted_uid_mapping({"userId": (False, "login_id")}))
        for mapping in ({}, {"preferred_username": (False, "login_id")},
                        {"email": (True, "login_id")}, {"userId": (True, "uid")}):
            with self.subTest(mapping=mapping):
                self.assertFalse(trusted_uid_mapping(mapping))

    def test_exact_uid_reuses_opaque_native_owner_and_validates_subject(self):
        self.assertEqual(choose_uid_owner(
            "123", [("opaque@auth.local", "123")], [],
            provider="authentik", subject="subject-a"), "opaque@auth.local")
        self.assertEqual(choose_uid_owner(
            "123", [("opaque@auth.local", "123")],
            [("opaque@auth.local", "authentik", "subject-a")],
            provider="authentik", subject="subject-a"), "opaque@auth.local")

    def test_collisions_and_missing_owner_deny_without_email_fallback(self):
        for profiles, bindings in (
            ([], []),
            ([("old@auth.local", "employee")], []),
            ([("native@auth.local", "123"), ("other@auth.local", "123")], []),
            ([("cfadmin@auth.local", "123")], []),
            ([("opaque@auth.local", "123")],
             [("other@auth.local", "authentik", "subject-a")]),
            ([("opaque@auth.local", "123")],
             [("opaque@auth.local", "AUTHENTIK", "subject-a")]),
        ):
            with self.subTest(profiles=profiles, bindings=bindings):
                with self.assertRaises(UIDBindingError):
                    choose_uid_owner("123", profiles, bindings,
                                     provider="authentik", subject="subject-a")

    def test_invalid_uid_alias_and_subject(self):
        for uid in ("", "123 ", "１２３", "123" + chr(0)):
            with self.subTest(uid=uid), self.assertRaises(UIDBindingError):
                choose_uid_owner(uid, [("opaque@auth.local", "123")], [],
                                 provider="authentik", subject="subject-a")
        with self.assertRaises(UIDBindingError):
            choose_uid_owner("123", [("opaque@auth.local", "123")], [],
                             provider="authentik", subject="wrong" + chr(10))


if __name__ == "__main__":
    unittest.main()
