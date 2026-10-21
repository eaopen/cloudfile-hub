"""Status protocol fixtures only; not a real daemon/import completion test."""
import json
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.migration.native_status import decode_status, NativeImportStatus


class NativeImportStatusTests(unittest.TestCase):
    repo = "11111111-1111-4111-8111-111111111111"

    def raw(self, state="done", **changes):
        return json.dumps(dict(repos=[dict(id=self.repo, state=state, **changes)], sync_errors=[])).encode()

    def test_idle_or_done_never_proves_import_complete(self):
        for state in ("done", "waiting for sync", "uploading", "error", "auto sync disabled"):
            value = decode_status(self.raw(state), self.repo)
            self.assertEqual(value["native_state"], state)
            self.assertIs(value["import_verified"], False)

    def test_duplicate_library_and_invalid_progress_are_rejected(self):
        for raw in (b'{"repos":[],"repos":[],"sync_errors":[]}',
                json.dumps(dict(repos=[dict(id=self.repo, state="done")] * 2, sync_errors=[])).encode(),
                self.raw(progress=True), self.raw(progress=-1), self.raw(progress=101), self.raw(progress=float("nan"))):
            with self.assertRaises(ContractError):
                decode_status(raw, self.repo)

    def test_native_messages_and_other_library_errors_are_not_exposed(self):
        raw = json.dumps(dict(repos=[dict(id=self.repo, state="error", error="private diagnostic")],
            sync_errors=[dict(repo_id=self.repo, error="private path"), dict(repo_id="other")])).encode()
        value = decode_status(raw, self.repo)
        self.assertEqual(value["recent_error_count"], 1)
        self.assertNotIn("private", repr(value))

    def test_configuration_cannot_be_supplied_as_relative_command(self):
        with self.assertRaises(ValueError):
            NativeImportStatus(executable="seaf-cli", confdir="/isolated/config")
