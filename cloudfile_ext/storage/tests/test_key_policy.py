"""Standalone auto-local key checks; no Django setup needed."""
import unittest

from cloudfile_ext.storage.key_policy import valid_repo_key


class StableRepoKeyTests(unittest.TestCase):
    def test_valid_cases(self):
        for key in ("a", "a1-b2", "stp-tech-mgmt-prepstd",
                    "c2ea4bbf-24ac-4d7c-94c2-b36fdbd3ad1d",
                    "a" * 80):
            with self.subTest(key=key):
                self.assertTrue(valid_repo_key(key))

    def test_invalid_cases(self):
        for key in ("", "-", "-a", "a-", "a/b", "../outside", "A",
                    "a:b", "a\\\\b", "a_b", "中", "a\n", "a" * 81,
                    None, [], 5):
            with self.subTest(key=key):
                self.assertFalse(valid_repo_key(key))


if __name__ == "__main__":
    unittest.main()
