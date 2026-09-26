"""Internal envelope cases only; not native publication/authorization evidence."""
import json
import unittest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.locks.commit_conditions import NativeLeaseConditions


class LeaseCommitEnvelopeTests(unittest.TestCase):
    def conditions(self):
        return NativeLeaseConditions("native", json.dumps(dict(
            path="/file.prt", context={}, scopes=[], oidc_session={},
            lease=dict(base_version="a" * 40))), "a" * 40)

    def test_separates_file_version_from_branch_head(self):
        value = self.conditions()
        envelope = json.loads(value.for_head("b" * 40))
        self.assertEqual(envelope["head_id"], "b" * 40)
        self.assertEqual(envelope["lease"]["base_version"], "a" * 40)
        self.assertNotIn("head_id", json.loads(value.encoded))
        self.assertNotIn("native", repr(value))

    def test_rejects_noncanonical_head_and_unknown_fields(self):
        for head in (None, "a" * 39, "A" * 40, "z" * 40):
            with self.assertRaises(ContractError):
                self.conditions().for_head(head)
        malformed = NativeLeaseConditions("native", '{"path":"/file"}', "a" * 40)
        with self.assertRaises(ContractError):
            malformed.for_head("b" * 40)
