"""Does the reviewed V2 cf_dir_acl satisfy directory ACL and shared-root needs?

Definition under test: the V2 contract only (`dev`). No legacy column, no
migration of old data. Runs against a disposable MariaDB: CF_ACL_TEST_MYSQL_PORT
and CF_ACL_TEST_SERVER are required, as in test_acl_store_mysql.
"""
import os
from pathlib import Path
from contextlib import contextmanager
from hashlib import sha256
from unittest import TestCase, skipUnless
from uuid import uuid4

import pymysql
from cloudfile_ext.v2.acl_policy import Principal, PolicyError, Rule, resolve
from cloudfile_ext.v2.acl_store import ACLStore
from cloudfile_ext.v2.schema import FreshSchema

RID = '00000000-0000-4000-8000-000000000001'
OTHER_RID = '00000000-0000-4000-8000-000000000002'
REV = '00000000-0000-4000-8000-000000000010'
INSERT = ('INSERT INTO cf_dir_acl(repo_id,path,path_hash,subject_type,provider,namespace,external_id,'
          'permission,inherit,share_mode,revision) VALUES(%s,%s,UNHEX(SHA2(%s,256)),%s,%s,%s,%s,%s,%s,%s,%s)')


@skipUnless(os.environ.get('CF_ACL_TEST_MYSQL_PORT'), 'disposable MariaDB required')
class SchemaContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = 'req_' + uuid4().hex
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
            c.execute('CREATE TABLE Branch (repo_id CHAR(36),name VARCHAR(10),commit_id CHAR(40),'
                      'PRIMARY KEY(repo_id,name)) ENGINE=InnoDB')
            c.execute("INSERT INTO Branch VALUES(%s,'master',%s)", [RID, 'a' * 40])

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        with cls.admin.cursor() as c:
            c.execute('DROP DATABASE ' + cls.schema)
        cls.admin.close()

    def setUp(self):
        with self.conn.cursor() as c:
            c.execute('DELETE FROM cf_dir_acl')

    def store(self):
        @contextmanager
        def atomic():
            self.conn.begin()
            try:
                yield
                self.conn.commit()
            finally:
                self.conn.rollback()
        return ACLStore(self.conn, self.schema, atomic)

    def insert(self, path='/shared', subject=('user', 'user', 'uid'), permission='r', inherit=1,
               share=0, provider='etech', repo_id=RID, revision=REV):
        # subject is (subject_type, namespace, external_id); provider is separate.
        with self.conn.cursor() as c:
            c.execute(INSERT, [repo_id, path, path.encode(), subject[0], provider, subject[1], subject[2],
                               permission, inherit, share, revision])

    def rejects(self, **row):
        # MariaDB reports a failed CHECK as 4025; a duplicate key is IntegrityError.
        with self.assertRaises((pymysql.IntegrityError, pymysql.OperationalError)):
            self.insert(**row)

    def test_permission_inherit_and_share_domains_are_enforced_by_the_table(self):
        # Exactly the stored values acl_policy accepts; everything else is refused
        # by the table itself, not only by application validation.
        for permission in ('r', 'rw', 'invisible'):
            self.insert(path='/p-' + permission, permission=permission)
        for bad in ('none', 'a', 'rwx', ''):
            self.rejects(path='/bad-' + bad, permission=bad)
        self.rejects(subject=('dept', 'dept', 'd1'))
        self.rejects(subject=('docs', 'docs', 'd1'))
        self.rejects(inherit=2)
        self.rejects(share=2)
        # A shared root must be readable directory content, never the library root.
        self.rejects(permission='invisible', share=1)
        self.rejects(path='/', share=1)
        self.insert(path='/', permission='r', share=0)

    def test_natural_key_is_repo_path_and_verified_subject_per_provider(self):
        self.insert()
        self.rejects(revision=str(uuid4()))  # same rule: one physical row, CAS by revision
        self.insert(provider='native-local')  # another provider is another rule
        self.insert(subject=('role', 'role', 'r1'))
        self.insert(subject=('user', 'user', 'uid2'))
        self.insert(repo_id=OTHER_RID)  # same path in another library
        with self.conn.cursor() as c:
            c.execute('SELECT COUNT(*) FROM cf_dir_acl')
            self.assertEqual(c.fetchone()[0], 5)

    def test_every_v2_query_has_an_index(self):
        with self.conn.cursor() as c:
            c.execute("SELECT index_name,GROUP_CONCAT(column_name ORDER BY seq_in_index) "
                      "FROM information_schema.statistics WHERE table_schema=DATABASE() "
                      "AND table_name='cf_dir_acl' GROUP BY index_name")
            indexes = dict(c.fetchall())
        # Candidate ancestors, list_path and the CAS all filter repo_id + path_hash,
        # and the per-library snapshot filters repo_id alone: both are PK prefixes.
        self.assertTrue(indexes['PRIMARY'].startswith('repo_id,path_hash'))
        # Shared roots: exact subject and provider first, then the share flag.
        self.assertEqual(indexes['acl_shared_subject'],
                         'provider,subject_type,namespace,external_id,share_mode,repo_id')
        digest = sha256(b'/shared').digest()
        for statement, args in (
                ('SELECT * FROM cf_dir_acl WHERE repo_id=%s AND path_hash IN (%s,%s)', [RID, digest, digest.hex()]),
                ('SELECT * FROM cf_dir_acl WHERE repo_id=%s', [RID]),
                ('SELECT * FROM cf_dir_acl WHERE provider=%s AND share_mode=1', ['etech'])):
            with self.conn.cursor() as c:
                c.execute('EXPLAIN ' + statement, args if '%s' in statement else None)
                plan = c.fetchone()
            self.assertIsNotNone(plan[5], statement)  # key: no full table scan

    def test_directory_acl_and_shared_root_semantics_survive_a_round_trip(self):
        # Sparse directory rules: user > org > role, inheritance, invisible deny.
        self.insert(path='/shared', subject=('user', 'user', 'uid'), permission='rw')
        self.insert(path='/shared/team', subject=('role', 'role', 'r1'), permission='r', share=1)
        self.insert(path='/shared/team/secret', subject=('user', 'user', 'uid'), permission='invisible')
        store = self.store()
        member = Principal('etech', 'uid', frozenset({('role', 'role', 'r1')}))
        self.assertEqual(sorted(r.path for r in store.library(RID)),
                         ['/shared', '/shared/team', '/shared/team/secret'])
        self.assertEqual(len(store.candidates(RID, '/shared/team/file', member)), 2)
        granted = (r.path for r, _ in store.shared(member))
        self.assertEqual(list(granted), ['/shared/team'])
        self.assertEqual(store.list_path(RID, '/shared', 'etech')[0][0].permission, 'rw')
        self.assertEqual([r.path for r, _ in store.list_path(RID, '/shared', 'native-local')], [])

        # Decisions on the stored rows. A user rule outranks a group rule at any
        # depth, so the personal rw inherits over the role grant below it; the
        # personal deny hides its own child; a group-only member gets the role r.
        self.assertEqual(resolve(RID, '/shared', member, 'rw', store.library(RID)).permission, 'rw')
        self.assertEqual(resolve(RID, '/shared/team/x', member, 'rw', store.library(RID)).permission, 'rw')
        self.assertFalse(resolve(RID, '/shared/team/secret/a', member, 'rw', store.library(RID)).can_read)
        role_only = Principal('etech', 'uid2', frozenset({('role', 'role', 'r1')}))
        self.assertEqual(resolve(RID, '/shared/team/x', role_only, None, store.library(RID)).permission, 'r')
        self.assertFalse(resolve(RID, '/shared', role_only, None, store.library(RID)).can_read)
        # A non-member qualifies only at the shared root, never in its library.
        outsider = Principal('etech', 'other', frozenset({('role', 'role', 'r1')}))
        self.assertTrue(resolve(RID, '/shared/team', outsider, None, store.library(RID)).can_read)
        self.assertFalse(resolve(RID, '/shared', outsider, None, store.library(RID)).can_read)

    def test_path_column_matches_the_canonical_path_contract(self):
        # Canonical paths are bounded to 4096 UTF-8 bytes; the column must hold
        # that, including multi-byte characters, without truncating a hash.
        long_path = '/' + '/'.join(['a' * 100] * 40)  # 4040 bytes, under the bound
        self.insert(path=long_path)
        self.insert(path='/目录/😀')
        store = self.store()
        self.assertEqual(store.list_path(RID, long_path, 'etech')[0][0].path, long_path)
        self.assertEqual(store.list_path(RID, '/目录/😀', 'etech')[0][0].path, '/目录/😀')
        too_long = '/' + 'a' * 4096
        with self.assertRaises(PolicyError):
            Rule(RID, too_long, 'etech', 'user', 'user', 'uid', 'r')  # rejected before SQL
        self.assertTrue(sha256(long_path.encode()).digest())
