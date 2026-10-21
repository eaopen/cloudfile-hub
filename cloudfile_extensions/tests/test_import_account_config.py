"""Actual Linux FD/seal boundaries, not evidence of native import authorization."""
from configparser import ConfigParser
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.migration.account_config import import_account_config


class UnsupportedAccountConfigTests(unittest.TestCase):
    def test_missing_proc_support_has_no_plaintext_fallback(self):
        with patch("cloudfile_extensions.migration.account_config.os.path.isdir", return_value=False):
            with self.assertRaises(ContractError) as error:
                with import_account_config("/not-used/private/account"):
                    self.fail("unavailable platform must not yield credentials")
        self.assertEqual(error.exception.code, "IMPORT_ACCOUNT_UNAVAILABLE")


@unittest.skipUnless(hasattr(os, "memfd_create") and os.path.isdir("/proc/self/fd"), "actual Linux memfd required")
class ImportAccountConfigTests(unittest.TestCase):
    def account(self, root):
        path = Path(root, "account.ini")
        path.write_text("[account]\nserver=https://cloudfile.invalid\nuser=native%tech\ntoken=" + "a" * 40 + "\n")
        path.chmod(0o600)
        return path

    def test_snapshot_survives_original_replacement_and_native_interpolation(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.account(root)
            with import_account_config(str(path)) as config:
                path.unlink()
                path.write_text("invalid replacement")
                parser = ConfigParser()
                parser.read(config.cli_path)
                self.assertEqual(parser.get("account", "user"), "native%tech")
                self.assertEqual(parser.get("account", "token"), "a" * 40)
                self.assertEqual(repr(config), "ImportAccountConfig()")
                self.assertEqual(config.pass_fds, (config.descriptor,))

    def test_seals_reject_write_and_truncate_and_scope_closes_fd(self):
        with tempfile.TemporaryDirectory() as root:
            with import_account_config(str(self.account(root))) as config:
                descriptor = config.descriptor
                for change in (lambda: os.write(descriptor, b"replace"), lambda: os.ftruncate(descriptor, 0)):
                    with self.assertRaises(OSError) as error:
                        change()
                    self.assertEqual(error.exception.errno, errno.EPERM)
            with self.assertRaises(OSError) as error:
                os.fstat(descriptor)
            self.assertEqual(error.exception.errno, errno.EBADF)

    def test_child_reopens_same_inherited_snapshot_without_credential_argv(self):
        with tempfile.TemporaryDirectory() as root:
            with import_account_config(str(self.account(root))) as config:
                # Local isolated Python child only, never seaf-cli or a service.
                script = "import configparser,sys; c=configparser.ConfigParser(); c.read(sys.argv[1]); assert c.get('account','user')=='native%tech'; assert c.get('account','token')=='a'*40"
                result = subprocess.run([sys.executable, "-c", script, config.cli_path],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    close_fds=True, pass_fds=config.pass_fds, timeout=5,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                self.assertEqual(result.returncode, 0)

    def test_caller_error_still_closes_descriptor_without_masking_error(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(RuntimeError, "caller failure"):
                with import_account_config(str(self.account(root))) as config:
                    descriptor = config.descriptor
                    raise RuntimeError("caller failure")
            with self.assertRaises(OSError):
                os.fstat(descriptor)
