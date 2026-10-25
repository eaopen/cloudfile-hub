"""Independent depth-contract vectors, no CE database or Django setup."""
import unittest

from cloudfile_ext.v2.errors import IdentityUnavailable
from cloudfile_ext.v2.org_depth import org_parent_map, scoped_memberships


def org(key, parent=None, namespace='directory'):
    return {'subject_type': 'org', 'namespace': namespace,
            'external_id': key, 'name': key,
            'parent_external_id': parent}


class OrgDepthContractTests(unittest.TestCase):
    def setUp(self):
        # Level 1=root ... level 5=leaf. Second branch confirms multi-Org.
        self.entries = [org('root'), org('l2', 'root'), org('l3', 'l2'),
                        org('l4', 'l3'), org('leaf', 'l4'),
                        org('branch', 'root'),
                        {'subject_type': 'role', 'namespace': 'role',
                         'external_id': 'approver', 'name': 'Approver'}]
        self.parents = org_parent_map(self.entries)
        self.direct = {('org', 'directory', 'leaf'),
                       ('role', 'role', 'approver')}

    def org_ids(self, level, direct=None):
        result = scoped_memberships(
            self.direct if direct is None else direct, self.parents, org_level=level)
        self.assertIn(('role', 'role', 'approver'), result)
        return {key[2] for key in result if key[0] == 'org'}

    def test_one_two_three_and_all_depths_on_five_level_tree(self):
        self.assertEqual(self.org_ids(1), {'leaf'})
        self.assertEqual(self.org_ids(2), {'leaf', 'l4'})
        self.assertEqual(self.org_ids(3), {'leaf', 'l4', 'l3'})
        self.assertEqual(self.org_ids(5), {'leaf', 'l4', 'l3', 'l2', 'root'})
        self.assertEqual(self.org_ids(0), {'leaf', 'l4', 'l3', 'l2', 'root'})
        self.assertEqual(self.org_ids(20), self.org_ids(0))

    def test_multi_org_and_role_never_inherits_org_rule(self):
        direct = self.direct | {('org', 'directory', 'branch')}
        self.assertEqual(self.org_ids(1, direct), {'leaf', 'branch'})
        self.assertEqual(self.org_ids(2, direct), {'leaf', 'l4', 'branch', 'root'})
        self.assertEqual(self.org_ids(0, direct),
                         {'leaf', 'l4', 'l3', 'l2', 'root', 'branch'})
        self.assertNotIn(('role', 'directory', 'root'),
                         scoped_memberships(direct, self.parents, org_level=0))

    def test_org_scope_never_crosses_namespace_even_with_identical_ids(self):
        entries = self.entries + [org('root', namespace='other'),
                                  org('leaf', 'root', namespace='other')]
        parents = org_parent_map(entries)
        result = scoped_memberships({('org', 'other', 'leaf')}, parents, org_level=0)
        self.assertEqual(result, frozenset({
            ('org', 'other', 'leaf'), ('org', 'other', 'root')}))

    def test_bad_or_incomplete_parent_graph_is_rejected_wholly(self):
        bad = [
            [org('leaf', 'missing')],
            [org('root'), org('root')],
            [org('a', 'b'), org('b', 'a')],
            [org('a', 'b'), org('b', 'c'), org('c', 'a')],
            [org('self', 'self')],
            [org('child', parent='')],
            [org('child', parent=12)],
            [{'subject_type': 'role', 'namespace': 'role',
              'external_id': 'x', 'parent_external_id': 'parent'}],
            [{}],
            'broken',
        ]
        for entries in bad:
            with self.subTest(entries=entries), self.assertRaises(IdentityUnavailable):
                org_parent_map(entries)

    def test_scoped_projection_refuses_unknown_org_or_invalid_depth(self):
        for level in (True, -1, 1.5, 16385):
            with self.subTest(level=level), self.assertRaises(IdentityUnavailable):
                scoped_memberships(self.direct, self.parents, org_level=level)
        with self.assertRaises(IdentityUnavailable):
            scoped_memberships({('org', 'directory', 'missing')},
                               self.parents, org_level=0)
        # Source failure cannot silently downgrade a missing Org to a role.
        with self.assertRaises(IdentityUnavailable):
            scoped_memberships({('group', 'directory', 'leaf')},
                               self.parents, org_level=1)


if __name__ == '__main__':
    unittest.main()
