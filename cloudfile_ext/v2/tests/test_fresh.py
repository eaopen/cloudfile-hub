"""Run against a disposable database populated from actual CE14 CREATE DDL.

Native RPC/HTTP is not emulated as an acceptance result: creation adapters below
are SQL fixtures; full login/transfer validation must run the real CE services.
"""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import unittest
from unittest.mock import Mock
from uuid import uuid4

from cloudfile_ext.v2.errors import IdentityConflict, IdentityUnavailable
from cloudfile_ext.v2.identity import NativeIdentity
from cloudfile_ext.v2.memberships import GroupCatalog, Memberships
from cloudfile_ext.v2.schema import FreshSchema, SchemaError, TABLES, statements


class DDLTest(unittest.TestCase):
    def test_only_three_create_statements_are_accepted(self):
        ddl = os.environ.get('CF_V2_DDL')
        if not ddl:
            self.skipTest('requires reviewed V2 DDL path')
        content = Path(ddl).read_text()
        self.assertEqual(set(statements(content)), TABLES)
        for extra in ('CREATE TABLE cf_background_job(id INT);', 'DROP TABLE Repo;', 'ALTER TABLE cf_dir_acl ADD bad INT;'):
            with self.assertRaises(SchemaError):
                statements(content + extra)


@unittest.skipUnless(os.environ.get('CF_TEST_DB_PORT') and os.environ.get('CF_TEST_REDIS_PORT'), 'isolated MariaDB/Redis required')
class FreshDatabaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pymysql
        import redis
        cls.admin = pymysql.connect(host='127.0.0.1', port=int(os.environ['CF_TEST_DB_PORT']),
                                    user='root', charset='utf8mb4', autocommit=True)
        cls.redis = redis.Redis(host='127.0.0.1', port=int(os.environ['CF_TEST_REDIS_PORT']))
        cls.ddl = Path(os.environ['CF_V2_DDL']).read_text()
        # Exported CE source is the test input, never the modified fork's SQL.
        source = Path(os.environ['CF_V2_SOURCE'])
        cls.native_ddl = {
            'account': (source / 'seafile-server/scripts/sql/mysql/ccnet.sql').read_text(),
            'hub': (source / 'seahub/sql/mysql.sql').read_text(),
            'files': (source / 'seafile-server/scripts/sql/mysql/seafile.sql').read_text(),
        }

    @classmethod
    def tearDownClass(cls):
        cls.admin.close()
        cls.redis.close()

    def setUp(self):
        import pymysql
        self.names = {kind: 'cfv2_' + uuid4().hex for kind in self.native_ddl}
        try:
            with self.admin.cursor() as cursor:
                for kind, name in self.names.items():
                    cursor.execute('CREATE DATABASE ' + name + ' CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci')
                    cursor.execute('USE ' + name)
                    # The upstream SQL dump intentionally disables FK checks
                    # while creating tables in dump order, before their targets.
                    cursor.execute('SET FOREIGN_KEY_CHECKS=0')
                    for match in re.finditer(r'CREATE TABLE[\s\S]+?;', self.native_ddl[kind]):
                        cursor.execute(match[0])
                    cursor.execute('SET FOREIGN_KEY_CHECKS=1')
            self.connection = pymysql.connect(host='127.0.0.1', port=int(os.environ['CF_TEST_DB_PORT']), user='root',
                                              database=self.names['files'], charset='utf8mb4', autocommit=True)
            self.schema = FreshSchema(self.connection, self.ddl)
            self.schema.install()
            def create_account(username):
                with self.admin.cursor() as cursor:
                    cursor.execute('INSERT INTO ' + self.names['account'] + '.EmailUser(email,passwd,is_staff,is_active,ctime) VALUES(%s,%s,0,1,0)', (username, '!'))
            self.identity = NativeIdentity(self.connection, account_schema=self.names['account'], hub_schema=self.names['hub'],
                                           issuer='https://idp.example.test/application/o/files/', create_account=create_account)
            self.username = self.identity.bind(subject='subject-one', uid='uid-1', login_name='E001')
            self.key = None
        except BaseException:
            self._drop()
            raise

    def _drop(self):
        with self.admin.cursor() as cursor:
            for name in self.names.values():
                cursor.execute('DROP DATABASE IF EXISTS ' + name)

    def tearDown(self):
        if self.key:
            self.redis.delete(self.key)
        self.connection.close()
        self._drop()

    def query(self, sql, args=()):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, args)
            return cursor.fetchall()

    def subject(self, *, status='active', roles=None):
        return dict(userId='uid-1', status=status, attributes={'login_name': 'E001'}, organizations=[], organization_ancestors=[],
                    roles=[] if roles is None else roles, etag='current', generated_at=datetime.now(timezone.utc).isoformat())

    def projector(self, fetch):
        result = Memberships(self.connection, self.redis, self.identity, account_schema=self.names['account'],
                             provider='etech', fetch=fetch, ttl=30)
        self.key = result._key('uid-1', self.username)
        return result

    def group(self, kind='role', external_id='r1', provider='etech'):
        def create(name):
            with self.admin.cursor() as cursor:
                cursor.execute('INSERT INTO ' + self.names['account'] + '.`Group`(group_name,creator_name,timestamp,parent_group_id) VALUES(%s,%s,0,0)', (name, 'native-admin'))
                return cursor.lastrowid
        return GroupCatalog(self.connection, account_schema=self.names['account'], provider=provider,
                            create_group=create).ensure(kind, 'business', external_id, 'Display Name')

    def test_schema_is_independent_retryable_and_exactly_three_tables(self):
        self.schema.install()
        self.schema.verify()
        self.assertEqual({row[0] for row in self.query('SHOW TABLES') if row[0].startswith('cf_')}, TABLES)
        self.assertNotIn('cf_schema_migration', {row[0] for row in self.query('SHOW TABLES')})

    def test_drift_does_not_get_repaired_or_migrate_legacy_data(self):
        self.query('ALTER TABLE cf_sso_group_map DROP INDEX sso_native_group')
        with self.assertRaises(SchemaError):
            self.schema.install()
        self.query('CREATE TABLE cf_managed_library(repo_id CHAR(36))')
        with self.assertRaises(SchemaError):
            self.schema.verify()
        self.assertIn(('cf_managed_library',), self.query('SHOW TABLES'))

    def test_native_repo_storage_shared_and_version_facts_are_untouched(self):
        # Use native definitions, including actual native columns and indexes.
        repo = str(uuid4())
        self.query('INSERT INTO Repo(repo_id) VALUES(%s)', (repo,))
        self.query('INSERT INTO RepoStorageId(repo_id,storage_id) VALUES(%s,%s)', (repo, 'native-backend'))
        self.query('INSERT INTO RepoOwner(repo_id,owner_id) VALUES(%s,%s)', (repo, self.username))
        self.query('INSERT INTO Branch(repo_id,name,commit_id) VALUES(%s,%s,%s)', (repo, 'master', 'a' * 40))
        self.query('INSERT INTO SharedRepo(repo_id,from_email,to_email,permission) VALUES(%s,%s,%s,%s)', (repo, self.username, 'native-user', 'r'))
        before = {table: self.query('SELECT * FROM ' + table) for table in ('Repo', 'RepoStorageId', 'RepoOwner', 'Branch', 'SharedRepo')}
        self.schema.install()
        self.assertEqual(before, {table: self.query('SELECT * FROM ' + table) for table in before})

    def test_storage_key_is_unique_and_survives_retirement(self):
        repo = str(uuid4())
        self.query("INSERT INTO cf_library_storage VALUES('reserved-key',%s,'retired')", (repo,))
        with self.assertRaises(Exception):
            self.query("INSERT INTO cf_library_storage VALUES('reserved-key',%s,'reserved')", (str(uuid4()),))
        self.assertEqual(self.query('SELECT repo_id,state FROM cf_library_storage'), ((repo, 'retired'),))

    def test_internal_sharing_never_attaches_to_deny_or_library_root(self):
        import pymysql
        for permission, path, shared in (('none', '/project', 0), ('invisible', '/project', 1), ('r', '/', 1)):
            with self.assertRaises(pymysql.MySQLError):
                self.query('INSERT INTO cf_dir_acl VALUES(%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s)',
                           (str(uuid4()), b'x' * 32, path, 'user', 'etech', 'user', 'uid-1', permission, shared, str(uuid4())))

    def test_renamed_login_keeps_account_and_uid_cannot_change(self):
        self.assertEqual(self.identity.bind(subject='subject-one', uid='uid-1', login_name='E999'), self.username)
        with self.assertRaises(IdentityConflict):
            self.identity.bind(subject='subject-one', uid='uid-2', login_name='E001')

    def test_second_verified_login_binding_reuses_native_account_and_permissions(self):
        role = self.group()
        self.query('INSERT INTO ' + self.names['account'] + '.GroupUser(group_id,user_name,is_staff) VALUES(%s,%s,0)',
                   (role, self.username))
        self.identity.create_account = Mock(side_effect=AssertionError('must reuse native account'))
        self.assertEqual(self.identity.bind(subject='another-subject', uid='uid-1', login_name='E001'), self.username)
        self.assertEqual(self.query('SELECT email FROM ' + self.names['account'] + '.EmailUser'), ((self.username,),))
        self.assertEqual(self.query('SELECT group_id,user_name FROM ' + self.names['account'] + '.GroupUser'),
                         ((role, self.username),))
        self.assertEqual(self.identity.bind(subject='another-subject', uid='uid-1', login_name='renamed'), self.username)
        with self.assertRaises(IdentityConflict):
            self.identity.bind(subject='another-subject', uid='uid-2', login_name='E001')

    def test_native_oauth_profile_can_be_claimed_without_another_account(self):
        self.query('DELETE FROM ' + self.names['hub'] + '.social_auth_usersocialauth')
        self.identity.create_account = Mock(side_effect=AssertionError('must reuse native account'))
        self.assertEqual(self.identity.bind(subject='verified-oidc-sub', uid='uid-1', login_name='E001'), self.username)
        self.query('UPDATE ' + self.names['account'] + '.EmailUser SET is_active=0 WHERE email=%s', (self.username,))
        with self.assertRaises(IdentityUnavailable):
            self.identity.bind(subject='third-sub', uid='uid-1', login_name='E001')

    def test_collation_alias_uid_is_rejected(self):
        with self.assertRaises(IdentityConflict):
            self.identity.bind(subject='another-subject', uid='UID-1', login_name='E001')

    def test_namespaced_group_catalog_does_not_merge_display_names(self):
        one = self.group('role', 'same')
        two = self.group('org', 'same')
        three = self.group('role', 'same', provider='another')
        self.assertEqual(self.group('role', 'same'), one)
        self.assertEqual(len({one, two, three}), 3)

    def test_ttl_refresh_only_changes_this_providers_current_user(self):
        role = self.group()
        other = self.group(provider='another')
        self.query('INSERT INTO ' + self.names['account'] + '.GroupUser(group_id,user_name,is_staff) VALUES(%s,%s,1)', (other, self.username))
        fetch = Mock(return_value=self.subject(roles=[{'namespace': 'business', 'external_id': 'r1'}]))
        projector = self.projector(fetch)
        projector.ensure('uid-1', self.username)
        projector.ensure('uid-1', self.username)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(self.query('SELECT group_id,is_staff FROM ' + self.names['account'] + '.GroupUser ORDER BY group_id'), ((role, 0), (other, 1)))
        self.redis.delete(self.key)  # exact TTL expiry without sleeping
        fetch.return_value = self.subject()
        projector.ensure('uid-1', self.username)
        self.assertEqual(self.query('SELECT group_id,is_staff FROM ' + self.names['account'] + '.GroupUser'), ((other, 1),))

    def test_expired_source_failure_is_unavailable_and_does_not_extend_ttl(self):
        role = self.group()
        fetch = Mock(return_value=self.subject(roles=[{'namespace': 'business', 'external_id': 'r1'}]))
        projector = self.projector(fetch)
        projector.ensure('uid-1', self.username)
        self.redis.delete(self.key)
        fetch.side_effect = TimeoutError('source unavailable')
        with self.assertRaises(IdentityUnavailable):
            projector.ensure('uid-1', self.username)
        self.assertIsNone(self.redis.get(self.key))
        self.assertEqual(self.query('SELECT group_id FROM ' + self.names['account'] + '.GroupUser'), ((role,),))

    def test_missing_map_and_changed_native_hierarchy_cannot_publish_readiness(self):
        projector = self.projector(lambda uid: self.subject(roles=[{'namespace': 'business', 'external_id': 'r1'}]))
        with self.assertRaises(IdentityUnavailable):
            projector.ensure('uid-1', self.username)
        role = self.group()
        self.query('UPDATE ' + self.names['account'] + '.`Group` SET parent_group_id=-1 WHERE group_id=%s', (role,))
        with self.assertRaises(IdentityUnavailable):
            projector.ensure('uid-1', self.username)
        self.assertIsNone(self.redis.get(self.key))

    def test_disabled_subject_clears_owned_members_only_and_is_not_ready(self):
        role = self.group()
        fetch = Mock(return_value=self.subject(roles=[{'namespace': 'business', 'external_id': 'r1'}]))
        projector = self.projector(fetch)
        projector.ensure('uid-1', self.username)
        fetch.return_value = self.subject(status='disabled')
        with self.assertRaises(IdentityUnavailable):
            projector.ensure('uid-1', self.username, force=True)
        self.assertFalse(self.query('SELECT group_id FROM ' + self.names['account'] + '.GroupUser WHERE group_id=%s', (role,)))
        self.assertIsNone(self.redis.get(self.key))

    def test_native_group_staff_is_never_demoted_by_projection(self):
        role = self.group()
        self.query('INSERT INTO ' + self.names['account'] + '.GroupUser(group_id,user_name,is_staff) VALUES(%s,%s,1)', (role, self.username))
        projector = self.projector(lambda uid: self.subject())
        with self.assertRaises(IdentityUnavailable):
            projector.ensure('uid-1', self.username)
        self.assertEqual(self.query('SELECT is_staff FROM ' + self.names['account'] + '.GroupUser'), ((1,),))
