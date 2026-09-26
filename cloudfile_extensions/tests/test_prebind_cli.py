"""Operator config/input boundaries; database path covered by SQL bindings tests."""
import io
import json
import os
import tempfile
import unittest
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.prebind_cli import load_config, process


class PrebindCLITest(unittest.TestCase):
    def setUp(self):
        self.row = dict(userId="u1", username="private@example.invalid", subject="private-sub", reason="approved")
        self.management = Mock()
        self.management.prebind.return_value = (self.row["username"], True)

    def test_default_checks_and_apply_reports_without_identifiers(self):
        for apply, expected in ((False, "would_bind"), (True, "bound")):
            output = []
            self.assertEqual(process(self.management, "https://idp.example.invalid/",
                io.StringIO(json.dumps(self.row) + "\n"), output.append, apply=apply), 0)
            self.assertEqual(output, [dict(line=1, status=expected)])
            self.assertEqual(self.management.prebind.call_args.kwargs["dry_run"], not apply)

    def test_duplicate_keys_limits_and_database_failure_stop(self):
        for raw in ('{"userId":"u1","userId":"u2"}\n', "x" * 16385, json.dumps(self.row)):
            output = []
            self.assertEqual(process(self.management, "https://idp.example.invalid/", io.StringIO(raw), output.append), 1)
            self.assertEqual(output[0]["status"], "failed")
        self.management.prebind.assert_not_called()
        self.management.prebind.side_effect = ContractError("IDENTITY_UNAVAILABLE", "private SQL", 503)
        output = []
        self.assertEqual(process(self.management, "https://idp.example.invalid/",
            io.StringIO((json.dumps(self.row) + "\n") * 2), output.append, apply=True), 1)
        self.assertEqual(output, [dict(line=1, status="failed", code="IDENTITY_UNAVAILABLE")])

    def test_private_config_rejects_open_permissions_symlink_and_duplicate_keys(self):
        config = dict(database=dict(CLOUDFILE_DB_HOST="localhost", CLOUDFILE_DB_USER="operator", CLOUDFILE_DB_NAME="seafile"),
            native_schema="ccnet", identity_schema="seahub", directory_provider="directory", actor_user_id="admin",
            issuer="https://idp.example.invalid/")
        with tempfile.TemporaryDirectory(prefix="cf-prebind-config-") as directory:
            path = os.path.join(directory, "operator.json")
            with open(path, "w") as target:
                json.dump(config, target)
            os.chmod(path, 0o600)
            self.assertEqual(load_config(path), config)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                load_config(path)
            os.chmod(path, 0o600)
            link = os.path.join(directory, "link")
            os.symlink(path, link)
            with self.assertRaises(OSError):
                load_config(link)
            with open(path, "w") as target:
                target.write('{"database":{},"database":{}}')
            with self.assertRaises(ValueError):
                load_config(path)
