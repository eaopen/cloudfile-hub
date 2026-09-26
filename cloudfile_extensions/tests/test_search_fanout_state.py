from unittest import TestCase

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.execution import step_hash
from cloudfile_extensions.search.fanout_store import SearchFanoutStore


class FanoutStateTest(TestCase):
    def setUp(self):
        uid = "11111111-1111-1111-1111-111111111111"
        self.value = dict(repo_id=uid, tag_id=uid, tag_revision=uid, upper_uid=uid, after_uid=None,
            next_uid=None, batch=0, index_uid="resources", payload="[]",
            payload_hash=step_hash("resources", "replace", b"[]"), state="pending")

    def decode(self):
        return SearchFanoutStore.decode(tuple(self.value[name] for name in SearchFanoutStore.FIELDS.split(",")))

    def test_empty_pending_page_still_requires_exact_frozen_hash(self):
        self.assertEqual(self.decode()["payload"], "[]")
        self.value["payload_hash"] = "a" * 64
        with self.assertRaises(ContractError):
            self.decode()

    def test_corrupt_cursor_or_page_is_rejected(self):
        for name, value in (("batch", True), ("payload", "[NaN]"), ("after_uid", "99999999-9999-9999-9999-999999999999")):
            original = self.value[name]
            self.value[name] = value
            with self.assertRaises(ContractError):
                self.decode()
            self.value[name] = original

    def test_scanned_state_cannot_retain_pending_payload(self):
        self.value["state"] = "scanned"
        with self.assertRaises(ContractError):
            self.decode()
