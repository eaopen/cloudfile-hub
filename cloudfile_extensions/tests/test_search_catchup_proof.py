import json
from unittest import TestCase

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.catchup import plan_receipts_complete
from cloudfile_extensions.search.execution import step_hash
from cloudfile_extensions.search.plans import encode_plan


class CatchupPlanProofTest(TestCase):
    def setUp(self):
        self.steps = [dict(operation="delete", payload=["a" * 64]), dict(operation="delete", payload=["b" * 64])]
        raw, digest = encode_plan("resources", self.steps)
        self.plan = (digest, raw.decode("utf-8"))
        self.receipts = [(position, step_hash("resources", "delete", json.dumps(step["payload"], separators=(",", ":")).encode()), "succeeded", position + 1) for position, step in enumerate(self.steps)]

    def test_full_receipts_required_not_just_plan_presence(self):
        self.assertTrue(plan_receipts_complete("resources", self.plan, self.receipts))
        for receipts in ([], self.receipts[:1], self.receipts + [self.receipts[0]], list(reversed(self.receipts))):
            self.assertFalse(plan_receipts_complete("resources", self.plan, receipts))

    def test_changed_hash_or_unknown_task_is_not_complete(self):
        for receipt in ((0, "c" * 64, "succeeded", 1), (0, self.receipts[0][1], "submitted", 1), (0, self.receipts[0][1], "succeeded", None), (False, self.receipts[0][1], "succeeded", 1)):
            self.assertFalse(plan_receipts_complete("resources", self.plan, [receipt, self.receipts[1]]))

    def test_wrong_physical_index_or_corrupt_plan_is_rejected(self):
        with self.assertRaises(ContractError):
            plan_receipts_complete("other", self.plan, self.receipts)
        with self.assertRaises(ContractError):
            plan_receipts_complete("resources", ("0" * 64, self.plan[1]), self.receipts)
