"""Stored-row decoding stays on the V2 contract: BINARY(32) path_hash.

A cell of any other shape means the table is not the V2 one, which is a
server-side fault (503), not a caller mistake (400). No database required.
"""
from hashlib import sha256
from unittest import TestCase

from cloudfile_ext.v2.acl_policy import PolicyError, Rule, StoredACLError
from cloudfile_ext.v2.acl_store import decode, path_digest

RID = '00000000-0000-4000-8000-000000000001'
REV = '00000000-0000-4000-8000-000000000010'
RULE = Rule(RID, '/shared', 'external', 'user', 'user', 'uid', 'rw', True, True)
DIGEST = path_digest('/shared')


def row(rule=RULE, hash_value=DIGEST, revision=REV):
    return (rule.repo_id, rule.path, rule.provider, rule.subject_type, rule.namespace,
            rule.external_id, rule.permission, int(rule.inherit), int(rule.share_mode),
            revision, hash_value)


class DecodeTests(TestCase):
    def test_binary_contract_row_is_accepted(self):
        self.assertEqual(path_digest('/shared'), sha256(b'/shared').digest())
        for value in (DIGEST, bytearray(DIGEST), memoryview(DIGEST)):
            self.assertEqual(decode(row(hash_value=value)), (RULE, REV))

    def test_text_hash_is_named_as_a_stored_fault(self):
        # bytes() on str used to raise TypeError, which the HTTP layer reported as
        # INVALID_ACL_REQUEST/400 and consumers read as an ACL outage.
        for value in (DIGEST.hex(), DIGEST.hex().encode()[:32].decode('latin-1')):
            with self.assertRaises(StoredACLError) as caught:
                decode(row(hash_value=value))
            self.assertIn('not binary', str(caught.exception))
            self.assertNotIsInstance(caught.exception, TypeError)

    def test_corrupt_rows_never_decode_to_a_rule(self):
        for broken in (row(hash_value=path_digest('/elsewhere')),
                       row(hash_value=DIGEST[:16]),
                       row(hash_value=None),
                       row(revision='not-a-uuid'),
                       row(rule=Rule(RID, '/', 'external', 'user', 'user', 'uid', 'r'))[:10],
                       (RULE.repo_id, RULE.path, RULE.provider, RULE.subject_type, RULE.namespace,
                        RULE.external_id, RULE.permission, 2, 0, REV, DIGEST)):
            with self.assertRaises(StoredACLError):
                decode(broken)

    def test_stored_faults_remain_fail_closed_policy_errors(self):
        # Callers that only know PolicyError must still deny, never fall back.
        with self.assertRaises(PolicyError):
            decode(row(hash_value='x'))
