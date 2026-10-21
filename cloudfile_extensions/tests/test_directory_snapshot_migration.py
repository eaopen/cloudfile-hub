"""v0.1 directory decisions retained across the namespace migration."""
import unittest

from cloudfile_extensions.directory import reconcile, snapshot


class DirectorySnapshotMigrationTest(unittest.TestCase):
    def test_department_parent_precedes_child_and_role_stays_flat(self):
        entries = snapshot.validate([
            {'external_id': 'child', 'name': 'Child', 'subject_type': 'dept',
             'parent_external_id': 'root', 'member_user_ids': ['User-1']},
            {'external_id': 'role:7', 'name': 'Role', 'subject_type': 'group',
             'member_user_ids': ['User-1']},
            {'external_id': 'root', 'name': 'Root', 'subject_type': 'dept',
             'member_user_ids': []},
        ])
        plan = reconcile.build(entries, {}, {})
        self.assertEqual(['root', 'child', 'role:7'],
                         [entry['external_id'] for entry in plan.create])

    def test_incomplete_member_binding_cannot_revoke_existing_access(self):
        entries = snapshot.validate([
            {'external_id': 'role:7', 'name': 'Role', 'subject_type': 'group',
             'member_user_ids': []},
        ])
        plan = reconcile.build(entries, {'role:7': {'group_id': 8, 'name': 'Role'}},
                               {8: ['seafile-user']}, quarantined={'role:7'})
        self.assertEqual([], plan.remove)

    def test_empty_feed_cannot_unmap_existing_group(self):
        with self.assertRaises(reconcile.SyncRefused):
            reconcile.build([], {'root': {'group_id': 8, 'name': 'Root'}}, {8: []})


if __name__ == '__main__':
    unittest.main()
