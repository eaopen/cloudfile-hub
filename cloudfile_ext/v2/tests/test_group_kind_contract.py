# -*- coding: utf-8 -*-
import unittest
from datetime import datetime, timezone

from cloudfile_ext.v2.errors import IdentityUnavailable
from cloudfile_ext.v2.memberships import STORED_KIND, SUBJECT_KIND, validate_subject, readiness_key

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


class DirectOrgMembershipTests(unittest.TestCase):
    def subject(self, *, status='active', ancestors=None):
        return dict(userId='user-A', status=status,
            attributes={'employee_no': 'E001'}, etag='version-1',
            organizations=[dict(namespace='directory', external_id='department')],
            organization_ancestors=([dict(namespace='directory', external_id='parent')]
                                    if ancestors is None else ancestors),
            roles=[dict(namespace='role', external_id='engineer')],
            generated_at=datetime.now(timezone.utc).isoformat())

    def test_default_org_level_one_does_not_grant_parent_or_ancestor(self):
        _, selected = validate_subject(self.subject(), 'user-A')
        self.assertEqual(selected, {
            ('org', 'directory', 'department'), ('role', 'role', 'engineer')})
        self.assertNotIn(('org', 'directory', 'parent'), selected)

    def test_ancestor_only_inputs_cannot_authorize_a_disabled_subject(self):
        value = self.subject(status='disabled')
        value['organizations'], value['roles'] = [], []
        with self.assertRaises(IdentityUnavailable):
            validate_subject(value, 'user-A')

    def test_duplicate_ancestor_and_direct_org_stays_invalid(self):
        value = self.subject(ancestors=[
            dict(namespace='directory', external_id='department')])
        with self.assertRaises(IdentityUnavailable):
            validate_subject(value, 'user-A')

    def test_changed_scope_version_invalidates_preexisting_readiness_marker(self):
        key = readiness_key('native-db', 'etech', 'user-A', 'user@auth.local')
        self.assertTrue(key.startswith('cfv2:subject-direct-v1:'))
        self.assertNotEqual(key, 'cfv2:subject:' + key.split(':')[-1])


if __name__ == '__main__':
    unittest.main()
