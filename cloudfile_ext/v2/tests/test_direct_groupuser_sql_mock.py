"""SQL control-flow regression for default direct-Org GroupUser projection.

Models native CE rows and transactional behavior; no real MariaDB or
Seafile process. Proves the reviewed _project() removes old ancestor grants,
preserves direct Org/Role and unrelated manual groups, and rolls back on error.
"""
from copy import deepcopy
from datetime import datetime, timezone
import unittest
from unittest.mock import Mock

from cloudfile_ext.v2.memberships import Memberships, validate_subject


DIRECT = ('org', 'directory', 'leaf')
PARENT = ('org', 'directory', 'parent')
ROLE = ('role', 'role', 'reviewer')
UID = 'user-9'
USERNAME = 'user9@auth.local'


def subject():
    return dict(userId=UID, status='active',
                generated_at=datetime.now(timezone.utc).isoformat(),
                etag='r1', attributes={'employee_no': 'E9'},
                organizations=[dict(namespace='directory', external_id='leaf')],
                organization_ancestors=[dict(namespace='directory', external_id='parent')],
                roles=[dict(namespace='role', external_id='reviewer')])


class Cursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = ()
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def fetchall(self):
        return self.rows
    def execute(self, sql, args=()):
        self.rows = ()
        maps = {('org', 'directory', 'leaf'): 10,
                ('org', 'directory', 'parent'): 11,
                ('role', 'role', 'reviewer'): 12}
        if sql.startswith('SELECT group_id,is_staff FROM '):
            self.rows = tuple(sorted(self.conn.members.items()))
        elif sql.startswith('SELECT group_id FROM cf_sso_group_map'):
            self.rows = tuple((gid,) for gid in maps.values() if gid in args[1:])
        elif sql.startswith('SELECT subject_type,namespace,external_id,group_id FROM cf_sso_group_map'):
            needed = {tuple(args[i:i + 3]) for i in range(1, len(args), 3)}
            self.rows = tuple((*key, gid) for key, gid in maps.items() if key in needed)
        elif sql.startswith('SELECT group_id,parent_group_id FROM '):
            self.rows = tuple((gid, 0) for gid in args)
        elif sql.startswith('DELETE FROM '):
            if self.conn.fail_delete and args[0] == 11:
                raise RuntimeError('simulated SQL failure')
            if args[0] in self.conn.members and self.conn.members[args[0]] == 0:
                del self.conn.members[args[0]]
        elif sql.startswith('INSERT INTO '):
            if args[0] in self.conn.members:
                raise RuntimeError('duplicate GroupUser')
            self.conn.members[args[0]] = 0
        else:
            raise AssertionError('unexpected SQL: ' + sql)


class Connection:
    def __init__(self, initial, *, fail_delete=False):
        self.members = dict(initial)
        self.snapshot = None
        self.fail_delete = fail_delete
        self.commits = self.rollbacks = 0
    def get_autocommit(self):
        return True
    def cursor(self):
        return Cursor(self)
    def begin(self):
        self.snapshot = deepcopy(self.members)
    def commit(self):
        self.snapshot = None
        self.commits += 1
    def rollback(self):
        if self.snapshot is not None:
            self.members = self.snapshot
            self.snapshot = None
            self.rollbacks += 1


class DirectGroupUserProjectionTests(unittest.TestCase):
    def projector(self, conn):
        identity = Mock()
        instance = Memberships(conn, Mock(), identity, account_schema='ccnet',
                               provider='external', fetch=lambda _: subject())
        return instance, identity

    def test_ancestor_is_revoked_direct_role_and_manual_group_preserved(self):
        conn = Connection({10: 0, 11: 0, 12: 0, 99: 0})
        projector, identity = self.projector(conn)
        _, desired = validate_subject(subject(), UID)
        self.assertEqual(desired, {DIRECT, ROLE})
        projector._project(UID, USERNAME, desired)
        self.assertEqual(conn.members, {10: 0, 12: 0, 99: 0})
        self.assertEqual(conn.commits, 1)
        identity.active.assert_called_with(USERNAME, UID, locked=True)
        projector._project(UID, USERNAME, desired)
        self.assertEqual(conn.members, {10: 0, 12: 0, 99: 0})
        self.assertEqual(conn.commits, 2)

    def test_failure_rolls_back_ancestor_revocation(self):
        conn = Connection({10: 0, 11: 0, 12: 0, 99: 0}, fail_delete=True)
        projector, _ = self.projector(conn)
        _, desired = validate_subject(subject(), UID)
        with self.assertRaisesRegex(RuntimeError, 'simulated SQL failure'):
            projector._project(UID, USERNAME, desired)
        self.assertEqual(conn.members, {10: 0, 11: 0, 12: 0, 99: 0})
        self.assertEqual((conn.commits, conn.rollbacks), (0, 1))

    def test_invalid_group_admin_is_rejected_without_changes(self):
        from cloudfile_ext.v2.errors import IdentityConflict
        conn = Connection({10: 1, 11: 0, 12: 0})
        projector, _ = self.projector(conn)
        _, desired = validate_subject(subject(), UID)
        with self.assertRaises(IdentityConflict):
            projector._project(UID, USERNAME, desired)
        self.assertEqual(conn.members, {10: 1, 11: 0, 12: 0})
        self.assertEqual((conn.commits, conn.rollbacks), (0, 1))


if __name__ == '__main__':
    unittest.main()
