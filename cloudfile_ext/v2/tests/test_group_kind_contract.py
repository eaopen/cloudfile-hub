# -*- coding: utf-8 -*-
import unittest

from cloudfile_ext.v2.memberships import STORED_KIND, SUBJECT_KIND

# Mirrors CONSTRAINT `sso_group_type` CHECK (subject_type in ('org','role')).
SCHEMA_KINDS = {'org', 'role'}


class GroupKindContractTests(unittest.TestCase):
    def test_written_kinds_are_allowed_by_the_schema(self):
        self.assertTrue(set(STORED_KIND.values()) <= SCHEMA_KINDS, STORED_KIND)

    def test_subject_kinds_map_back_to_the_v2_names(self):
        for kind in ('org', 'role'):
            self.assertEqual(SUBJECT_KIND[STORED_KIND[kind]], kind)

    def test_legacy_spellings_still_read_as_v2_kinds(self):
        # Older writers stored dept/group; rows may still carry them.
        self.assertEqual(SUBJECT_KIND['dept'], 'org')
        self.assertEqual(SUBJECT_KIND['group'], 'role')


if __name__ == '__main__':
    unittest.main()
