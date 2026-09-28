import unittest

from cloudfile_extensions.library_share_plan import plan


class Cursor:
    def __init__(self, ledger=(), maps=None):
        self.ledger = ledger
        self.maps = maps or {}
        self.query = None
        self.arguments = None

    def execute(self, query, arguments):
        self.query, self.arguments = query, arguments

    def fetchall(self):
        if 'cf_library_share_ledger' in self.query:
            return self.ledger
        return self.maps.get(self.arguments, ())


class LibrarySharePlanTest(unittest.TestCase):
    def test_full_desired_state_only_revokes_ledger_owned_shares(self):
        cursor = Cursor(ledger=(('old', 7, 'r', 'APPLIED'), ('same', 8, 'r', 'APPLIED')),
                        maps={('etech', 'dept', 'directory', 'new'): ((9,),),
                              ('etech', 'dept', 'directory', 'same'): ((8,),)})
        changes, errors = plan(cursor, 'repo', 'etech', {'new': 'rw', 'same': 'rw'})
        self.assertEqual(changes['add'], [('new', 9, 'rw')])
        self.assertEqual(changes['update'], [('same', 8, 'rw')])
        self.assertEqual(changes['revoke'], [('old', 7, None)])
        self.assertEqual(errors, [])
        self.assertIn('provider=%s AND subject_type=%s AND namespace=%s AND external_id=%s', cursor.query)

    def test_role_prefix_maps_to_role_namespace_and_unmapped_fails_closed(self):
        cursor = Cursor(maps={('etech', 'group', 'role', '42'): ((10,),)})
        changes, errors = plan(cursor, 'repo', 'etech', {'role:42': 'r', 'missing': 'rw'})
        self.assertEqual(changes['add'], [('role:42', 10, 'r')])
        self.assertEqual(errors, ['missing: group mapping is missing or ambiguous'])

    def test_group_rebinding_is_not_silently_published(self):
        cursor = Cursor(ledger=(('dept', 7, 'r', 'APPLIED'),),
                        maps={('etech', 'dept', 'directory', 'dept'): ((8,),)})
        changes, errors = plan(cursor, 'repo', 'etech', {'dept': 'rw'})
        self.assertEqual(changes, {'add': [], 'update': [], 'revoke': []})
        self.assertEqual(errors, ['dept: native group mapping changed; manual reconciliation required'])

    def test_pending_add_is_replanned_after_partial_native_write(self):
        cursor = Cursor(ledger=(('dept', 7, 'r', 'PENDING'),),
                        maps={('etech', 'dept', 'directory', 'dept'): ((7,),)})
        changes, errors = plan(cursor, 'repo', 'etech', {'dept': 'r'})
        self.assertEqual(changes['add'], [('dept', 7, 'r')])
        self.assertEqual(errors, [])

    def test_removed_pending_intent_is_revoked(self):
        cursor = Cursor(ledger=(('dept', 7, 'r', 'PENDING'),))
        changes, errors = plan(cursor, 'repo', 'etech', {})
        self.assertEqual(changes['revoke'], [('dept', 7, None)])
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
