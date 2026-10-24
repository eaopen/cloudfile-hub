"""Executable, portable Hub ACL decision vectors for #56.

JSON contains input/expected result only and can also be consumed by Server
C/Go contract tests. These prove the pure policy, not native file-byte checks
or the real Etech integration.
"""
import json
from pathlib import Path
import unittest

from cloudfile_ext.v2.acl_policy import (
    Decision, PolicyError, Principal, Rule, narrow_to_native, resolve,
)

FIXTURE = Path(__file__).parent / "fixtures" / "acl_effective_vectors.json"


class EffectiveACLContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_all_portable_effective_permission_vectors(self):
        data = self.data
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["policy_id"], "ce-pro-track-precedence-v1")
        cases = data["cases"]
        self.assertGreaterEqual(len(cases), 40)
        self.assertEqual(len({item["id"] for item in cases}), len(cases))
        for item in cases:
            with self.subTest(case=item["id"]):
                principal = Principal(
                    data["provider"], data["uid"],
                    frozenset(tuple(x) for x in data["groups"]),
                    active=item.get("active", True), ready=item.get("ready", True))
                rules = [
                    Rule(data["repo_id"], row["path"], data["provider"],
                         row["subject_type"], row["namespace"], row["external_id"],
                         row["permission"], row.get("inherit", True),
                         row.get("share_mode", False))
                    for row in item["rules"]
                ]
                actual = resolve(
                    data["repo_id"], item["path"], principal,
                    item["native"], rules,
                    hard_readonly=item.get("hard_readonly", False))
                expect = item["expected"]
                self.assertEqual(
                    (actual.permission, actual.qualified_root, actual.from_rule),
                    (expect["permission"], expect["qualified_root"], expect["from_rule"]))
                self.assertEqual(actual.can_read, expect["permission"] in ("r", "rw"))
                self.assertEqual(actual.can_write, expect["permission"] == "rw")
                self.assertEqual(actual.visible, expect["permission"] != "invisible")

    def test_absent_native_requires_real_shared_qualification(self):
        # This is the existing Hub+native boundary; a non-shared directory
        # rule must not become an independent authorization root.
        self.assertIsNone(narrow_to_native(Decision("rw", "/", True), None))
        self.assertIsNone(narrow_to_native(Decision("rw", "/", True), "none"))
        self.assertIsNone(narrow_to_native(Decision("rw", "/Shared", True), "invisible"))
        self.assertIsNone(narrow_to_native(Decision("r", "/Shared", False), None))
        self.assertEqual(narrow_to_native(Decision("r", "/Shared", True), None),
                         Decision("r", "/Shared", True))
        # CE library read is qualification, not a hard content-write ceiling.
        self.assertEqual(narrow_to_native(Decision("rw", "/", True), "r").permission, "rw")

    def test_invalid_and_conflicting_stored_rules_fail_closed(self):
        d = self.data
        principal = Principal(d["provider"], d["uid"])
        owned = Rule(d["repo_id"], "/A", d["provider"], "user",
                     "user", d["uid"], "r")
        for rules in ([owned, owned],
                      [Rule(d["repo_id"], "/A", "another-provider", "user",
                            "user", d["uid"], "rw")]):
            with self.subTest(rules=rules), self.assertRaises(PolicyError):
                resolve(d["repo_id"], "/A", principal, "rw", rules)
        with self.assertRaises(PolicyError):
            Rule(d["repo_id"], "/A", d["provider"], "user",
                 "user", d["uid"], "none")
        with self.assertRaises(PolicyError):
            Rule(d["repo_id"], "/A", d["provider"], "user",
                 "user", d["uid"], "invisible", share_mode=True)

    def test_publisher_mode_does_not_change_effective_permission(self):
        # Mode A publishes external desired state; B writes native UI/API.
        # Authority sees the SAME current Rule rows, never mode/ownership.
        d = self.data
        rules = [Rule(d["repo_id"], "/A", d["provider"], "user",
                      "user", d["uid"], "r")]
        principal = Principal(d["provider"], d["uid"])
        outcomes = {}
        for publisher in ("A-external", "B-cloudfile"):
            outcomes[publisher] = resolve(d["repo_id"], "/A", principal, "rw", rules)
        self.assertEqual(outcomes["A-external"], outcomes["B-cloudfile"])


if __name__ == "__main__":
    unittest.main()
