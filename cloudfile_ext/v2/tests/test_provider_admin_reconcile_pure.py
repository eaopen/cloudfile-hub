"""Single-user CE administrator reconciliation without MariaDB or network.

The fake connection verifies cross-schema SQL intent and transaction rollback.
Real CE RPC, multi-process locks and session/token gates remain DEV criteria.
"""
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_ext.v2.errors import IdentityUnavailable
from cloudfile_ext.v2.provider_admin_reconcile import (
    AdminNativeState, AdminOwnershipConflict, reconcile_native_admin, transition,
)


class AdminTransitionTests(TestCase):
    def test_nonstaff_verified_superadmin_may_be_promoted(self):
        self.assertEqual(transition(AdminNativeState(False, None), True), 'grant')
        self.assertEqual(transition(AdminNativeState(True, 'default_admin'), True), 'retain')

    def test_provider_revoke_changes_only_existing_default_admin(self):
        self.assertEqual(transition(AdminNativeState(True, 'default_admin'), False), 'revoke')
        self.assertEqual(transition(AdminNativeState(False, None), False), 'unchanged')

    def test_manual_native_administrators_remain_unmanaged(self):
        for role in (None, 'system_admin', 'daily_admin'):
            self.assertEqual(transition(AdminNativeState(True, role), False), 'unmanaged')
            with self.assertRaises(AdminOwnershipConflict):
                transition(AdminNativeState(True, role), True)
        with self.assertRaises(AdminOwnershipConflict):
            transition(AdminNativeState(False, 'default_admin'), True)

    def test_invalid_state_does_not_make_an_admin(self):
        for state in (AdminNativeState(1, None), AdminNativeState(False, ''),
                      AdminNativeState(False, 42), None):
            with self.subTest(state=state), self.assertRaises(AdminOwnershipConflict):
                transition(state, True)


class FakeDatabase:
    def __init__(self):
        self.username = 'person@auth.local'
        self.uid = 'uid-1'
        self.active = 1
        self.staff = 0
        self.role = None
        self.fail_role_write = False
        self.queries = []
        self.commits = 0
        self.rollbacks = 0
        self.snapshot = None

    def begin(self):
        self.snapshot = (self.staff, self.role)

    def commit(self):
        self.commits += 1
        self.snapshot = None

    def rollback(self):
        self.rollbacks += 1
        if self.snapshot is not None:
            self.staff, self.role = self.snapshot
        self.snapshot = None

    def cursor(self):
        return FakeCursor(self)


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.result = ()
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, sql, args=()):
        self.db.queries.append((sql, args))
        self.rowcount = 0
        if 'SELECT user,login_id' in sql:
            self.result = ((self.db.username, self.db.uid),)
        elif 'SELECT email,is_active,is_staff' in sql:
            self.result = ((self.db.username, self.db.active, self.db.staff),)
        elif 'SELECT role FROM' in sql:
            self.result = ((self.db.role,),) if self.db.role is not None else ()
        elif 'INSERT INTO' in sql and 'role_permissions_adminrole' in sql:
            if self.db.fail_role_write:
                raise RuntimeError('role storage failed')
            if self.db.role is not None:
                raise RuntimeError('existing role cannot be overwritten')
            self.db.role = args[1]
            self.rowcount = 1
        elif 'UPDATE' in sql and 'SET is_staff=1' in sql:
            self.rowcount = int(self.db.staff == 0 and self.db.active == 1)
            if self.rowcount:
                self.db.staff = 1
        elif 'UPDATE' in sql and 'SET is_staff=0' in sql:
            self.rowcount = int(self.db.staff == 1 and self.db.active == 1)
            if self.rowcount:
                self.db.staff = 0
        elif 'DELETE FROM' in sql and 'role_permissions_adminrole' in sql:
            self.rowcount = int(self.db.role == 'default_admin')
            self.db.role = None
        elif 'SELECT email,is_staff' in sql:
            self.result = ((self.db.username, self.db.staff),)
        else:
            raise AssertionError('unexpected SQL: ' + sql)
        return self.rowcount

    def fetchall(self):
        return self.result


class NativeReconcileTests(TestCase):
    def setUp(self):
        self.db = FakeDatabase()
        self.identity = SimpleNamespace(
            connection=self.db,
            accounts='`ccnet`.EmailUser',
            profiles='`seahub`.profile_profile',
            active=Mock(),
        )
        self.lock = patch('cloudfile_ext.v2.provider_admin_reconcile.database_lock',
                          side_effect=lambda *args: nullcontext())
        self.lock.start()
        self.addCleanup(self.lock.stop)

    def subject(self, wanted=True, status='active'):
        return dict(userId=self.db.uid, status=status, super_admin=wanted)

    def apply(self, subject=None, **kwargs):
        item = self.subject() if subject is None else subject
        fetch = Mock(return_value=item)
        result = reconcile_native_admin(
            self.identity, self.db.uid, self.db.username,
            fetch_subject=fetch, enabled=True, **kwargs)
        fetch.assert_called_once_with(self.db.uid)
        return result

    def test_grant_retain_revoke_are_atomic_and_verified(self):
        self.assertEqual(self.apply(), 'grant')
        self.assertEqual((self.db.staff, self.db.role), (1, 'default_admin'))
        self.assertEqual(self.apply(), 'retain')
        self.assertEqual(self.apply(self.subject(False)), 'revoke')
        self.assertEqual((self.db.staff, self.db.role), (0, None))
        self.assertEqual(self.db.commits, 3)
        self.assertTrue(any('FOR UPDATE' in sql for sql, _ in self.db.queries))
        self.assertTrue(all('cf_' not in sql for sql, _ in self.db.queries))

    def test_manual_native_admin_never_adopted(self):
        for role in (None, 'system_admin'):
            self.db.staff, self.db.role = 1, role
            with self.assertRaises(AdminOwnershipConflict):
                self.apply()
            self.assertEqual((self.db.staff, self.db.role), (1, role))
            self.assertEqual(self.apply(self.subject(False)), 'unmanaged')

    def test_role_storage_failure_rolls_back_and_does_not_elevate(self):
        self.db.fail_role_write = True
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assertEqual((self.db.staff, self.db.role), (0, None))
        self.assertEqual(self.db.commits, 0)
        self.assertGreaterEqual(self.db.rollbacks, 1)

    def test_false_or_missing_claim_cannot_elevate(self):
        self.assertEqual(self.apply(self.subject(False)), 'unchanged')
        with self.assertRaises(IdentityUnavailable):
            self.apply(dict(userId=self.db.uid, status='active'))
        self.assertEqual((self.db.staff, self.db.role), (0, None))

    def test_disabled_identity_revokes_and_conflicting_uid_is_refused(self):
        self.apply()
        self.assertEqual(self.apply(self.subject(False, 'disabled')), 'revoke')
        with self.assertRaises(IdentityUnavailable):
            self.apply(dict(userId='other-uid', status='active', super_admin=True))

    def test_no_opt_in_or_reserved_native_account_never_writes(self):
        with self.assertRaises(AdminOwnershipConflict):
            reconcile_native_admin(self.identity, self.db.uid, self.db.username,
                                   fetch_subject=lambda _: self.subject())
        with self.assertRaises(AdminOwnershipConflict):
            reconcile_native_admin(self.identity, self.db.uid, 'cfadmin@auth.local',
                                   fetch_subject=lambda _: self.subject(), enabled=True)
        self.assertEqual(self.db.queries, [])
        self.identity.active.assert_not_called()


if __name__ == '__main__':
    import unittest
    unittest.main()
