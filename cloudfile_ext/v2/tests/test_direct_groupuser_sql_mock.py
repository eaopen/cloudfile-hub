"""SQL control-flow regression for default direct-Org GroupUser projection.

Models native CE rows and transactional behavior; no real MariaDB or
Seafile process. Proves the reviewed _project() removes old ancestor grants,
preserves direct Org/Role and unrelated manual groups, and rolls back on error.
"""
import ast
from pathlib import Path
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import unittest
from unittest.mock import Mock, patch

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
        maps = self.conn.maps
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
        self.maps = {DIRECT: 10, PARENT: 11, ROLE: 12}
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

    def test_new_user_memberships_are_added_and_verified(self):
        # The old readback checked only groups already owned before INSERT,
        # rejecting a perfectly valid first login with new Org/Role rows.
        for original in ({99: 0}, {10: 0, 99: 0}):
            with self.subTest(original=original):
                conn = Connection(original)
                projector, identity = self.projector(conn)
                projector._project(UID, USERNAME, {DIRECT, ROLE})
                self.assertEqual(conn.members, {10: 0, 12: 0, 99: 0})
                self.assertEqual((conn.commits, conn.rollbacks), (1, 0))
                identity.active.assert_called_once_with(USERNAME, UID, locked=True)

    def test_missing_role_or_org_does_not_block_known_grants_or_revocations(self):
        # Catalog lag must neither grant an unknown group nor preserve a
        # revoked ancestor; unrelated native/manual memberships stay intact.
        for missing in (('role', 'role', 'new-role'), ('org', 'directory', 'new-org')):
            with self.subTest(missing=missing):
                conn = Connection({10: 0, 11: 0, 99: 0})
                projector, _ = self.projector(conn)
                with self.assertLogs('cloudfile_ext.v2.memberships', level='WARNING') as logs:
                    projector._project(UID, USERNAME, {DIRECT, ROLE, missing})
                self.assertEqual(conn.members, {10: 0, 12: 0, 99: 0})
                self.assertIn('missing_count=1', logs.output[0])
                self.assertIn('retry=next_sso_login', logs.output[0])
                self.assertNotIn(USERNAME, logs.output[0])
                self.assertEqual(conn.commits, 1)

    def test_next_login_force_refreshes_newly_synchronized_role_inside_ttl(self):
        conn = Connection({99: 0})
        del conn.maps[ROLE]
        projector, identity = self.projector(conn)
        projector._key = Mock(return_value='subject-key')
        with patch('cloudfile_ext.v2.memberships.database_lock', side_effect=lambda *args: nullcontext()), \
             patch('cloudfile_ext.v2.memberships.is_ready', return_value=True):
            with self.assertLogs('cloudfile_ext.v2.memberships', level='WARNING'):
                projector.ensure(UID, USERNAME, force=True)
            self.assertEqual(conn.members, {10: 0, 99: 0})
            projector.redis.set.assert_called_once()
            # Catalog sync alone changes no user membership. The login boundary
            # consumes the new mapping even while the old marker is valid.
            conn.maps[ROLE] = 12
            projector.ensure(UID, USERNAME)
            self.assertEqual(conn.members, {10: 0, 99: 0})
            projector.ensure(UID, USERNAME, force=True)
            self.assertEqual(conn.members, {10: 0, 12: 0, 99: 0})
            self.assertEqual(conn.commits, 2)

    def test_sso_callback_forces_adapter_and_membership_refresh(self):
        # Execute the actual adapter function without importing the CE/Django
        # service graph; also verify the real OAuth call opts into that path.
        root = Path(__file__).resolve().parents[3]
        tree = ast.parse((root / 'seahub/oauth/views.py').read_text())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == 'ensure_subject']
        self.assertEqual(len(calls), 1)
        self.assertTrue(any(k.arg == 'force' and isinstance(k.value, ast.Constant)
                            and k.value.value is True for k in calls[0].keywords))
        tree = ast.parse((root / 'cloudfile_ext/v2/directory_adapter.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == 'ensure_subject')
        memberships = Mock()
        ready = Mock(return_value=True)
        runtime = Mock(side_effect=lambda: nullcontext((None, None, None, memberships)))
        namespace = dict(subject_ready=ready, runtime=runtime)
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<adapter>', 'exec'), namespace)
        namespace['ensure_subject'](UID, USERNAME, force=True)
        ready.assert_not_called()
        memberships.ensure.assert_called_once_with(UID, USERNAME, force=True)

    def test_all_missing_grants_allow_no_implicit_access(self):
        conn = Connection({10: 0, 12: 0, 99: 0})
        projector, _ = self.projector(conn)
        with self.assertLogs('cloudfile_ext.v2.memberships', level='WARNING'):
            projector._project(UID, USERNAME, {('role', 'role', 'unsynced')})
        self.assertEqual(conn.members, {99: 0})

    def test_catalog_lag_does_not_hide_native_admin_conflict(self):
        from cloudfile_ext.v2.errors import IdentityConflict
        conn = Connection({10: 1, 99: 0})
        projector, _ = self.projector(conn)
        with self.assertLogs('cloudfile_ext.v2.memberships', level='WARNING'), \
             self.assertRaises(IdentityConflict):
            projector._project(UID, USERNAME, {DIRECT, ('role', 'role', 'unsynced')})
        self.assertEqual(conn.members, {10: 1, 99: 0})
        self.assertEqual(conn.commits, 0)

    def test_disabled_subject_and_directory_failure_still_refuse_login(self):
        from cloudfile_ext.v2.errors import IdentityUnavailable
        conn = Connection({10: 0, 12: 0, 99: 0})
        projector, _ = self.projector(conn)
        projector._key = Mock(return_value='subject-key')
        disabled = subject()
        disabled.update(status='disabled', organizations=[], organization_ancestors=[], roles=[])
        with patch('cloudfile_ext.v2.memberships.database_lock', side_effect=lambda *args: nullcontext()):
            with self.assertRaisesRegex(IdentityUnavailable, 'disabled'):
                projector.ensure(UID, USERNAME, force=True, subject=disabled)
            self.assertEqual(conn.members, {99: 0})
            projector.redis.set.assert_not_called()
            projector.fetch = Mock(side_effect=TimeoutError())
            with self.assertRaises(IdentityUnavailable):
                projector.ensure(UID, USERNAME, force=True)
            projector.redis.set.assert_not_called()

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
