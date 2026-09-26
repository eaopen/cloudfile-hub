"""Private account filesystem boundaries; no actual credential authentication."""
import os
from pathlib import Path
import tempfile
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.migration.native_account import read_import_account


class NativeImportAccountTests(unittest.TestCase):
    def account(self, root, text=None):
        path = Path(root, "account.ini")
        path.write_text(text or "[account]\nserver=https://cloudfile.invalid\nuser=native-user\ntoken=" + "a" * 40 + "\n")
        path.chmod(0o600)
        return path

    def test_reads_private_fixed_account_without_revealing_values(self):
        with tempfile.TemporaryDirectory() as root:
            result = read_import_account(str(self.account(root)))
            self.assertEqual(result.native_username, "native-user")
            self.assertEqual(result.token, "a" * 40)
            self.assertEqual(repr(result), "NativeImportAccount()")

    def test_public_permissions_and_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.account(root)
            path.chmod(0o644)
            with self.assertRaises(ContractError):
                read_import_account(str(path))
            path.chmod(0o600)
            link = Path(root, "link")
            link.symlink_to(path)
            with self.assertRaises(ContractError):
                read_import_account(str(link))
            os.link(path, Path(root, "hardlink"))
            with self.assertRaises(ContractError):
                read_import_account(str(path))

    def test_password_fallback_http_and_extra_sections_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for text in ("[account]\nserver=http://cloudfile.invalid\nuser=u\ntoken=" + "a" * 40,
                    "[account]\nserver=https://cloudfile.invalid\nuser=u\npassword=secret",
                    "[account]\nserver=https://cloudfile.invalid\nuser=u\ntoken=" + "a" * 40 + "\n[other]\nx=1"):
                with self.assertRaises(ContractError) as error:
                    read_import_account(str(self.account(root, text)))
                self.assertNotIn("secret", str(error.exception))
