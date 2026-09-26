from unittest import TestCase

from cloudfile_extensions.search.plans import encode_plan


class SearchPlanEncodingTest(TestCase):
    def test_exact_operations_and_payloads_are_bound(self):
        raw, digest = encode_plan("resources", [dict(operation="delete", payload=["a" * 64])])
        self.assertIn(b'"delete"', raw)
        self.assertNotEqual(digest, encode_plan("resources", [dict(operation="delete", payload=["b" * 64])])[1])
        self.assertNotEqual(digest, encode_plan("other", [dict(operation="delete", payload=["a" * 64])])[1])

    def test_unsupported_operation_and_unbounded_payload_rejected(self):
        for steps in ([], [dict(operation="reset", payload=["x"])], [dict(operation="delete", payload=["x"] * 101)]):
            with self.assertRaises(ValueError):
                encode_plan("resources", steps)
