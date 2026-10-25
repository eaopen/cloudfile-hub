"""Run only against a disposable schema: CF_ACL_TEST_MYSQL_PORT is required."""
import os
from pathlib import Path
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest import TestCase, skipUnless
from uuid import uuid4

import pymysql
from cloudfile_ext.v2.acl_store import ACLStore, RevisionConflict
from cloudfile_ext.v2.acl_policy import Rule, Principal, PolicyError
from cloudfile_ext.v2.schema import FreshSchema

RID = '00000000-0000-4000-8000-000000000001'


@skipUnless(os.environ.get('CF_ACL_TEST_MYSQL_PORT'), 'disposable MariaDB required')
class ACLSQLTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = 'acl_' + uuid4().hex
        cls.options = dict(host='127.0.0.1', port=int(os.environ['CF_ACL_TEST_MYSQL_PORT']), user='root',
                           password='acl-test-only', autocommit=True, charset='utf8mb4')
        cls.admin = pymysql.connect(**cls.options)
        with cls.admin.cursor() as c:
            c.execute('CREATE DATABASE ' + cls.schema)
        cls.options['database'] = cls.schema
        cls.conn = pymysql.connect(**cls.options)
        server = Path(os.environ['CF_ACL_TEST_SERVER'])
        FreshSchema(cls.conn, (server / 'scripts/sql/mysql/cloudfile-v2.sql').read_text()).install()
        with cls.conn.cursor() as c:
            c.execute('CREATE TABLE Branch (repo_id CHAR(36),name VARCHAR(10),commit_id CHAR(40),PRIMARY KEY(repo_id,name)) ENGINE=InnoDB')
            c.execute("INSERT INTO Branch VALUES(%s,'master',%s)", [RID, 'a'*40])

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        with cls.admin.cursor() as c:
            c.execute('DROP DATABASE ' + cls.schema)
        cls.admin.close()

    def store(self, conn=None):
        conn = conn or self.conn
        @contextmanager
        def atomic():
            conn.begin()
            try:
                yield
                conn.commit()
            finally:
                conn.rollback()
        return ACLStore(conn, self.schema, atomic)

    def setUp(self):
        with self.conn.cursor() as c:
            c.execute('DELETE FROM cf_dir_acl')
        self.rule = Rule(RID, '/shared', 'external', 'user', 'user', 'uid', 'rw', True, True)
        self.principal = Principal('external', 'uid')
        self.revision = str(uuid4())

    def test_create_cas_replay_delete_and_conflict(self):
        store = self.store()
        store.mutate(self.rule, expected=None, revision=self.revision)
        store.mutate(self.rule, expected=None, revision=self.revision)
        self.assertEqual(store.candidates(RID, '/shared/sub', self.principal), [(self.rule, self.revision)])
        self.assertEqual(store.shared(self.principal), [(self.rule, self.revision)])
        with self.assertRaises(RevisionConflict):
            store.mutate(self.rule, expected=None, revision=str(uuid4()))
        store.mutate(self.rule, expected=self.revision, revision=str(uuid4()), delete=True)
        self.assertEqual(store.shared(self.principal), [])

    def test_subject_and_path_queries_do_not_leak_other_rules(self):
        store = self.store()
        store.mutate(self.rule, expected=None, revision=self.revision)
        self.assertEqual(store.candidates(RID, '/shared-sibling', self.principal), [])
        self.assertEqual(store.shared(Principal('external', 'other')), [])
        self.assertEqual(store.shared(Principal('other-provider', 'uid')), [])

    def test_library_read_and_committed_write_notification(self):
        changed = []
        store = self.store()
        store.changed = changed.append
        self.assertEqual(store.library(RID), ())
        store.mutate(self.rule, expected=None, revision=self.revision)
        store.mutate(self.rule, expected=None, revision=self.revision)  # replay: no change
        other = Rule(RID, '/other', 'external', 'role', 'role', 'r1', 'invisible')
        store.mutate(other, expected=None, revision=str(uuid4()))
        self.assertEqual(changed, [RID, RID])
        self.assertEqual(sorted(store.library(RID), key=lambda r: r.path), [other, self.rule])
        self.assertEqual(store.library('00000000-0000-4000-8000-000000000002'), ())
        with self.assertRaises(RevisionConflict):
            store.mutate(self.rule, expected=None, revision=str(uuid4()))
        self.assertEqual(changed, [RID, RID])

    def test_corrupt_hash_and_sql_failure_never_fall_back(self):
        store = self.store()
        store.mutate(self.rule, expected=None, revision=self.revision)
        with self.conn.cursor() as c:
            c.execute("UPDATE cf_dir_acl SET path='/elsewhere'")
        with self.assertRaises(PolicyError):
            store.shared(self.principal)
        with self.assertRaises(pymysql.Error):
            ACLStore(self.conn, 'missing_schema', lambda: None).shared(self.principal)

    def test_library_batch_atomic_owned_diff_and_one_invalidation(self):
        from cloudfile_ext.v2.acl_batch import fingerprint
        from cloudfile_ext.v2.acl_store import RevisionConflict
        store = self.store()
        changed = []
        store.changed = changed.append
        other = Rule(RID, '/external', 'external', 'role', 'role', 'external',
                     'r', True, False)
        unrelated = Rule(RID, '/other-provider', 'other', 'user', 'user', 'uid',
                         'r', True, False)
        store.mutate(self.rule, expected=None, revision=self.revision)
        store.mutate(other, expected=None, revision=str(uuid4()))
        store.mutate(unrelated, expected=None, revision=str(uuid4()))
        changed.clear()
        old = store.provider_snapshot(RID, 'external')
        managed = [('/shared', 'user', 'user', 'uid'),
                   ('/new', 'user', 'user', 'uid')]
        new = Rule(RID, '/new', 'external', 'user', 'user', 'uid', 'r', True, True)
        report = store.replace_owned(RID, 'external', expected=fingerprint(old),
                                     managed=managed, desired=[new])
        self.assertEqual((report['inserted'], report['deleted'], report['updated']), (1, 1, 0))
        self.assertEqual(changed, [RID])
        self.assertEqual([r.path for r, _ in store.shared(self.principal)], ['/new'])
        self.assertEqual({r.path for r, _ in store.provider_snapshot(RID, 'external')},
                         {'/new', '/external'})
        self.assertEqual(store.provider_snapshot(RID, 'other')[0][0], unrelated)
        self.assertEqual(report['fingerprint'], fingerprint(store.provider_snapshot(RID, 'external')))
        replay = store.replace_owned(RID, 'external', expected=report['fingerprint'],
                                     managed=managed, desired=[new])
        self.assertEqual((replay['inserted'], replay['updated'], replay['deleted']), (0, 0, 0))
        self.assertEqual(changed, [RID])
        with self.assertRaises(RevisionConflict):
            store.replace_owned(RID, 'external', expected=fingerprint(old),
                                managed=managed, desired=[new])
        self.assertEqual(changed, [RID])

    def test_writer_waits_for_native_branch_transaction(self):
        started, finished = Event(), Event()
        other = pymysql.connect(**self.options)
        def writer():
            started.set()
            try:
                self.store(other).mutate(self.rule, expected=None, revision=self.revision)
            finally:
                finished.set()
        self.conn.begin()
        with self.conn.cursor() as c:
            c.execute("SELECT commit_id FROM Branch WHERE repo_id=%s AND name='master' FOR UPDATE", [RID])
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(writer)
                self.assertTrue(started.wait(2))
                self.assertFalse(finished.wait(.2))
                self.conn.commit()
                future.result(timeout=5)
        finally:
            self.conn.rollback()
            other.close()
        self.assertEqual(self.store().shared(self.principal), [(self.rule, self.revision)])
