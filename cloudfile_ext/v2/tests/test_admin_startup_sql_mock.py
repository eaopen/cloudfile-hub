"""Model the one-shot SQL control flow without a live CE/MariaDB instance.

These mocked transaction tests complement, but do not replace, real DEV SQL
and SSO acceptance. They never create database objects.
"""
from contextlib import nullcontext
from copy import deepcopy
from unittest import TestCase
from unittest.mock import Mock, patch

from cloudfile_ext.v2.admin_startup import ROLE, sync_native_admins


class Cursor:
    def __init__(self, connection):
        self.conn = connection
        self.rows = ()
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def fetchall(self):
        return self.rows

    def execute(self, sql, args=()):
        self.conn.statements.append((sql, args))
        self.rows, self.rowcount = (), 0
        if self.conn.fail_write and sql.startswith('UPDATE ') and 'SET is_staff=1' in sql:
            raise RuntimeError('simulated CE write failure')
        states = self.conn.states
        if sql.startswith('SELECT a.email,p.login_id,e.is_staff,a.role'):
            self.rows = tuple((name, v['uid'], v['staff'], v['role'])
                              for name, v in states.items() if v['role'] == ROLE)
        elif sql.startswith('SELECT e.is_active,e.is_staff,p.login_id,a.role'):
            v = states.get(args[0])
            self.rows = ((v['active'], v['staff'], v['uid'], v['role']),) if v else ()
        elif sql.startswith('INSERT INTO ') and '(email,role) VALUES' in sql:
            v = states[args[0]]
            if v['role'] is not None:
                raise RuntimeError('duplicate role')
            v['role'], self.rowcount = args[1], 1
        elif sql.startswith('UPDATE ') and 'SET is_staff=1' in sql:
            v = states[args[0]]
            if v['active'] == 1 and v['staff'] == 0:
                v['staff'], self.rowcount = 1, 1
        elif sql.startswith('UPDATE ') and 'SET is_staff=0' in sql:
            v = states[args[0]]
            if v['staff'] == 1:
                v['staff'], self.rowcount = 0, 1
        elif sql.startswith('DELETE FROM ') and 'WHERE email=%s AND role=%s' in sql:
            v = states[args[0]]
            if v['role'] == args[1]:
                v['role'], self.rowcount = None, 1
        elif sql.startswith('SELECT is_staff FROM '):
            self.rows = ((states[args[0]]['staff'],),)
        elif sql.startswith('SELECT e.is_staff,p.login_id,a.role'):
            v = states[args[0]]
            self.rows = ((v['staff'], v['uid'], v['role']),) if v['role'] else ()
        else:
            raise AssertionError('unmodeled SQL: ' + sql)


class Connection:
    def __init__(self, states, *, fail_write=False):
        self.states = deepcopy(states)
        self.snapshot = None
        self.fail_write = fail_write
        self.statements = []
        self.commits = self.rollbacks = 0

    def cursor(self):
        return Cursor(self)

    def begin(self):
        if self.snapshot is not None:
            raise AssertionError('nested transaction')
        self.snapshot = deepcopy(self.states)

    def commit(self):
        self.snapshot = None
        self.commits += 1

    def rollback(self):
        if self.snapshot is not None:
            self.states = self.snapshot
            self.snapshot = None
        self.rollbacks += 1


def account(uid, *, staff=0, role=None):
    return {'uid': uid, 'staff': staff, 'role': role, 'active': 1}


def identity(conn):
    obj = Mock()
    obj.connection, obj.accounts = conn, 'ccnet.EmailUser'
    obj.profiles, obj.provider = 'hub.profile_profile', 'trusted-example'
    obj.prepare.side_effect = lambda *, uid, login_name, account: account + '@auth.local'
    return obj


class StartupSqlControlFlowTests(TestCase):
    def apply(self, instance, roster, **kwargs):
        with patch('cloudfile_ext.v2.admin_startup.database_lock', return_value=nullcontext()):
            return sync_native_admins(instance, roster, **kwargs)

    def test_grant_idempotent_repeat_and_native_admin_isolation(self):
        conn = Connection({'admin@auth.local': account('uid-9'),
                           'manual@auth.local': account('manual', staff=1, role=ROLE)})
        obj = identity(conn)
        first = self.apply(obj, (('uid-9', 'admin'),))
        self.assertEqual((first['added'], first['removed']), (1, 0))
        self.assertEqual(conn.states['admin@auth.local']['role'], ROLE)
        self.assertEqual(conn.states['admin@auth.local']['staff'], 1)
        self.assertEqual(conn.states['manual@auth.local']['staff'], 1)
        second = self.apply(obj, (('uid-9', 'admin'),))
        self.assertEqual((second['added'], second['removed'], second['kept']), (0, 0, 1))
        self.assertEqual(conn.commits, 2)

    def test_only_explicitly_managed_missing_account_is_revoked(self):
        conn = Connection({'admin@auth.local': account('uid-9', staff=1, role=ROLE),
                           'old@auth.local': account('old', staff=1, role=ROLE),
                           'native@auth.local': account('native', staff=1, role=ROLE)})
        outcome = self.apply(identity(conn), (('uid-9', 'admin'),),
                             managed_accounts=('old@auth.local',))
        self.assertEqual(outcome['removed'], 1)
        self.assertEqual((conn.states['old@auth.local']['staff'],
                          conn.states['old@auth.local']['role']), (0, None))
        self.assertEqual(conn.states['native@auth.local']['role'], ROLE)

    def test_failed_write_rolls_back_staff_and_role_transaction(self):
        conn = Connection({'admin@auth.local': account('uid-9')}, fail_write=True)
        obj = identity(conn)
        with self.assertRaisesRegex(RuntimeError, 'simulated CE write failure'):
            self.apply(obj, (('uid-9', 'admin'),))
        self.assertEqual(conn.states['admin@auth.local'], account('uid-9'))
        self.assertEqual((conn.commits, conn.rollbacks), (0, 1))


if __name__ == '__main__':
    import unittest
    unittest.main()
