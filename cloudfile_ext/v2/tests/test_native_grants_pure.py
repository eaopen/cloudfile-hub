"""Native Seafile CE library-grant API contract (no Django/database)."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from cloudfile_ext.v2.acl_policy import PolicyError
from cloudfile_ext.v2.acl_store import RevisionConflict
from cloudfile_ext.v2.native_grants import (
    MAX_GRANTS, NativeGrantUnavailable, NativeLibraryGrants, permission, target,
)

REPO = '00000000-0000-4000-8000-000000000001'
OWNER = 'owner@auth.local'


class CE:
    def __init__(self):
        self.owner = OWNER
        self.users = {'worker@auth.local': 'r'}
        self.groups = {7: 'rw'}
        self.writes = []
        self.drop_write = False

    def get_repo_owner(self, repo):
        return self.owner

    def list_repo_shared_to(self, owner, repo):
        return [SimpleNamespace(user=k, perm=v) for k, v in self.users.items()]

    def list_repo_shared_group_by_user(self, owner, repo):
        return [SimpleNamespace(group_id=k, perm=v) for k, v in self.groups.items()]

    def share_repo(self, repo, owner, user, level):
        self.writes.append(('add_user', user, level))
        if not self.drop_write:
            self.users[user] = level

    def set_share_permission(self, repo, owner, user, level):
        self.writes.append(('set_user', user, level))
        if not self.drop_write:
            self.users[user] = level

    def remove_share(self, repo, owner, user):
        self.writes.append(('del_user', user))
        if not self.drop_write:
            self.users.pop(user, None)

    def set_group_repo(self, repo, gid, owner, level):
        self.writes.append(('add_group', gid, level))
        if not self.drop_write:
            self.groups[gid] = level

    def set_group_repo_permission(self, gid, repo, level):
        self.writes.append(('set_group', gid, level))
        if not self.drop_write:
            self.groups[gid] = level

    def unset_group_repo(self, repo, gid, owner):
        self.writes.append(('del_group', gid))
        if not self.drop_write:
            self.groups.pop(gid, None)


class NativeLibraryGrantTests(TestCase):
    def setUp(self):
        self.native = CE()
        self.protected = set()
        self.valid_users = {'worker@auth.local', 'new@auth.local'}
        self.valid_groups = {7, 8}
        self.service = NativeLibraryGrants(
            self.native, REPO,
            user_exists=lambda u: u in self.valid_users,
            group_exists=lambda g: g in self.valid_groups,
            protected_admin=lambda typ, value: (typ, value) in self.protected)

    def test_lists_native_shares_without_creating_an_acl_shadow_table(self):
        data = self.service.list()
        self.assertEqual(data['source'], 'seafile-ce')
        self.assertEqual(data['owner'], OWNER)
        self.assertEqual(data['grants'], [
            {'subject_type': 'group', 'subject': 7, 'permission': 'rw'},
            {'subject_type': 'user', 'subject': 'worker@auth.local', 'permission': 'r'}])

    def test_grant_add_update_revoke_and_idempotent_retry(self):
        added = self.service.change('user', 'new@auth.local', expected=None, desired='rw')
        self.assertTrue(added['changed'])
        self.assertEqual(self.native.users['new@auth.local'], 'rw')
        retry = self.service.change('user', 'new@auth.local', expected='rw', desired='rw')
        self.assertFalse(retry['changed'])
        upgraded = self.service.change('user', 'worker@auth.local',
                                       expected='r', desired='rw')
        self.assertTrue(upgraded['changed'])
        deleted = self.service.change('user', 'worker@auth.local',
                                      expected='rw', desired=None)
        self.assertTrue(deleted['changed'])
        self.assertNotIn('worker@auth.local', self.native.users)
        self.assertEqual(len(self.native.writes), 3)

    def test_group_add_change_and_revoke(self):
        self.service.change('group', 8, expected=None, desired='r')
        self.service.change('group', 8, expected='r', desired='rw')
        self.service.change('group', 8, expected='rw', desired=None)
        self.assertNotIn(8, self.native.groups)
        self.assertEqual(self.native.writes[-3:],
                         [('add_group', 8, 'r'), ('set_group', 8, 'rw'),
                          ('del_group', 8)])

    def test_stale_expected_permission_is_conflict_not_overwrite(self):
        with self.assertRaises(RevisionConflict):
            self.service.change('user', 'worker@auth.local',
                                expected=None, desired='rw')
        self.assertEqual(self.native.writes, [])
        self.assertEqual(self.native.users['worker@auth.local'], 'r')

    def test_only_exact_native_user_or_group_is_accepted(self):
        for kind, subject in (('user', 'unknown'), ('user', ' worker@auth.local'),
                              ('group', True), ('group', '7'),
                              ('group', 0), ('role', 'role-admin')):
            with self.subTest(kind=kind, subject=subject), self.assertRaises(PolicyError):
                target(kind, subject)
        for value in ('admin', 'invisible', 'none', '', True, 1):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                permission(value)

    def test_owner_and_ce_admin_markers_cannot_be_modified(self):
        self.protected.add(('group', 7))
        with self.assertRaises(PolicyError):
            self.service.change('group', 7, expected='rw', desired='r')
        with self.assertRaises(PolicyError):
            self.service.change('group', 7, expected='rw', desired=None)
        with self.assertRaises(PolicyError):
            self.service.change('user', OWNER, expected=None, desired='rw')
        self.assertFalse(self.native.writes)

    def test_nonexistent_recipient_cannot_be_granted_ce_access(self):
        with self.assertRaises(PolicyError):
            self.service.change('user', 'missing@auth.local', expected=None, desired='r')
        with self.assertRaises(PolicyError):
            self.service.change('group', 9, expected=None, desired='r')
        self.assertEqual(self.native.writes, [])

    def test_postwrite_native_readback_failure_is_not_success(self):
        self.native.drop_write = True
        with self.assertRaises(NativeGrantUnavailable):
            self.service.change('user', 'new@auth.local', expected=None, desired='r')
        self.assertEqual(self.native.writes, [('add_user', 'new@auth.local', 'r')])

    def test_failed_or_oversize_native_snapshot_is_never_empty(self):
        self.native.list_repo_shared_to = Mock(return_value=None)
        with self.assertRaises(NativeGrantUnavailable):
            self.service.list()
        self.native.list_repo_shared_to = Mock(
            return_value=[SimpleNamespace(user='x%d@auth.local' % n, perm='r')
                          for n in range(MAX_GRANTS + 1)])
        with self.assertRaises(NativeGrantUnavailable):
            self.service.list()

    def test_unexpected_native_grant_or_duplicate_rejected(self):
        self.native.users['worker@auth.local'] = 'admin'
        with self.assertRaises(NativeGrantUnavailable):
            self.service.list()
        self.native.users['worker@auth.local'] = 'r'
        self.native.list_repo_shared_to = Mock(return_value=[
            SimpleNamespace(user='worker@auth.local', perm='r'),
            SimpleNamespace(user='worker@auth.local', perm='r')])
        with self.assertRaises(NativeGrantUnavailable):
            self.service.list()


if __name__ == '__main__':
    import unittest
    unittest.main()
