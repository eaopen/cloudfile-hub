"""Lightweight, dependency-free tests for startup-only administrator sync."""
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import Mock

from cloudfile_ext.v2.admin_startup import changes, managed_scope, sync_native_admins, validated_roster
from cloudfile_ext.v2.errors import IdentityUnavailable


class ProviderAdminRosterTests(unittest.TestCase):
    def roster(self, entries=None, *, issued=None, complete=True):
        return {
            'contract_version': '1.0', 'complete': complete,
            'generated_at': (issued or datetime.now(timezone.utc)).isoformat(),
            'admins': ([{'uid': 'external-9', 'account': 'admin'}]
                       if entries is None else entries),
        }

    def test_valid_single_and_multiple_sso_administrators(self):
        self.assertEqual(validated_roster(self.roster()),
                         (('external-9', 'admin'),))
        multiple = [{'uid': 'u1', 'account': 'admin'},
                    {'uid': 'u2', 'account': 'operator'}]
        self.assertEqual(validated_roster(self.roster(multiple)),
                         (('u1', 'admin'), ('u2', 'operator')))

    def test_optional_external_admin_compatibility_needs_verified_roster(self):
        self.assertEqual(validated_roster(self.roster(), required_account='admin'),
                         (('external-9', 'admin'),))
        with self.assertRaises(IdentityUnavailable):
            validated_roster(self.roster([{'uid': 'u2', 'account': 'operator'}]),
                             required_account='admin')
        self.assertEqual(validated_roster(self.roster([{'uid': 'u2', 'account': 'operator'}])),
                         (('u2', 'operator'),))

    def test_unavailable_or_incomplete_source_is_not_an_empty_revocation(self):
        cases = [
            self.roster(complete=False),
            self.roster([]),
            self.roster([{'uid': 'a', 'account': 'admin'}] * 33),
            self.roster(issued=datetime.now(timezone.utc) - timedelta(minutes=10)),
            self.roster(issued=datetime.now(timezone.utc) + timedelta(minutes=10)),
            dict(self.roster(), contract_version='old'),
            dict(self.roster(), generated_at='not a date'),
            dict(self.roster(), admins=''),
            self.roster([{'uid': 'a', 'account': 'cfadmin'}]),
            self.roster([{'uid': 'a', 'account': 'admin'},
                         {'uid': 'b', 'account': 'ADMIN'}]),
            self.roster([{'uid': 'a', 'account': 'admin'},
                         {'uid': 'a', 'account': 'newadmin'}]),
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(IdentityUnavailable):
                validated_roster(invalid)

    def test_startup_diff_is_idempotent_and_removes_stale_default_admin(self):
        current = {'old@auth.local': ('old-uid', True, 'default_admin'),
                   'admin@auth.local': ('uid-9', True, 'default_admin')}
        add, remove, keep = changes(
            current, {'admin@auth.local': 'uid-9', 'operator@auth.local': 'uid-10'},
            managed_accounts=('old@auth.local',))
        self.assertEqual(add, {'operator@auth.local'})
        self.assertEqual(remove, {'old@auth.local'})
        self.assertEqual(keep, {'admin@auth.local'})
        self.assertEqual(changes({'admin@auth.local': ('uid-9', True, 'default_admin')},
                                 {'admin@auth.local': 'uid-9'}),
                         (set(), set(), {'admin@auth.local'}))

    def test_unmanaged_native_admin_survives_missing_provider_roster(self):
        current = {'manual@auth.local': ('manual-uid', True, 'default_admin'),
                   'old@auth.local': ('old-uid', True, 'default_admin')}
        add, remove, keep = changes(current, {'new@auth.local': 'new-uid'})
        self.assertEqual(add, {'new@auth.local'})
        self.assertEqual(remove, set())
        add, remove, keep = changes(current, {'new@auth.local': 'new-uid'},
                                    managed_accounts=('old@auth.local',))
        self.assertEqual(remove, {'old@auth.local'})
        self.assertNotIn('manual@auth.local', remove)

    def test_invalid_scope_fails_before_native_account_precreation(self):
        identity = Mock()
        for invalid in (('cfadmin@auth.local',), ('dup@auth.local', 'dup@auth.local'),
                        (' bad@auth.local ',), ('',), tuple('u%d' % i for i in range(33)),
                        'admin@auth.local'):
            with self.subTest(invalid=invalid), self.assertRaises(IdentityUnavailable):
                sync_native_admins(identity, (('uid-9', 'admin'),), managed_accounts=invalid)
            identity.prepare.assert_not_called()
        self.assertEqual(managed_scope(()), frozenset())
        self.assertEqual(managed_scope(('old@auth.local',)), frozenset(('old@auth.local',)))

    def test_empty_or_oversized_apply_roster_is_rejected_before_any_write(self):
        # The command validates the roster, but the write function must also
        # refuse an empty plan instead of revoking every managed account.
        identity = Mock()
        cases = ((), [], tuple((str(i), 'admin') for i in range(33)),
                 'not-a-roster', None)
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaises(IdentityUnavailable):
                sync_native_admins(identity, invalid)
            identity.prepare.assert_not_called()

    def test_staff_or_other_role_is_never_adopted_as_external_admin(self):
        for state in (('same-uid', True, None),
                      ('same-uid', True, 'system_admin'),
                      ('same-uid', False, 'default_admin'),
                      ('other-uid', True, 'default_admin')):
            with self.subTest(state=state), self.assertRaises(IdentityUnavailable):
                changes({'user@auth.local': state}, {'user@auth.local': 'same-uid'})


if __name__ == '__main__':
    unittest.main()
