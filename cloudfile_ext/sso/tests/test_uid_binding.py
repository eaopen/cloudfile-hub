"""Pure UID regressions; runnable without DB, Django or an IdP."""
import unittest

from cloudfile_ext.sso.uid_binding import UIDBindingError, select_uid_owner


class UIDBindingPolicyTests(unittest.TestCase):
    def owner(self, profiles, bindings=(), uid='123', provider='authentik', subject='sub-1'):
        return select_uid_owner(uid, profiles, bindings,
                                provider=provider, subject=subject)

    def test_existing_uid_wins_despite_email_or_display_differences(self):
        self.assertEqual(self.owner([('opaque@auth.local', '123')]), 'opaque@auth.local')
        self.assertEqual(
            self.owner([('opaque@auth.local', '123')],
                       [('opaque@auth.local', 'authentik', 'sub-1')]),
            'opaque@auth.local')

    def test_missing_ambiguous_alias_or_conflicting_subject_refused(self):
        cases = [
            ([], []),
            ([('old@auth.local', 'employee-23')], []),
            ([('x@auth.local', '123'), ('y@auth.local', '123')], []),
            ([('cfadmin@auth.local', '123')], []),
            ([('opaque@auth.local', '123')], [('other@auth.local', 'authentik', 'sub-1')]),
            ([('opaque@auth.local', '123')], [('opaque@auth.local', 'AUTHENTIK', 'sub-1')]),
            ([('opaque@auth.local', '123')], [('opaque@auth.local', 'authentik', 'SUB-1')]),
        ]
        for profiles, bindings in cases:
            with self.subTest(profiles=profiles, bindings=bindings):
                with self.assertRaises(UIDBindingError):
                    self.owner(profiles, bindings)

    def test_uid_alias_and_invalid_subject_refused(self):
        for uid in ('123 ', '１２３', '123' + chr(0), ''):
            with self.subTest(uid=uid):
                with self.assertRaises(UIDBindingError):
                    self.owner([('opaque@auth.local', '123')], uid=uid)
        with self.assertRaises(UIDBindingError):
            self.owner([('opaque@auth.local', '123')], subject='bad' + chr(10) + 'sub')


if __name__ == '__main__':
    unittest.main()
