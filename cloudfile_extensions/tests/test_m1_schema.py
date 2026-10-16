"""Fresh M1 DDL and runtime against isolated MariaDB/Redis; no legacy import."""
from datetime import datetime, timezone
import os
import unittest
from unittest.mock import Mock
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.m1 import TABLES
from cloudfile_extensions.schema.runner import MigrationError, SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class M1SchemaTest(DatabaseTestCase):
    def runner(self):
        return SchemaRunner(self.connection, profile='m1')

    def test_fresh_inventory_repeat_and_automatic_runtime_detection(self):
        runner = self.runner()
        runner.apply()
        self.assertEqual({row[0] for row in runner._query('SHOW TABLES')}, TABLES)
        self.assertEqual(len(TABLES), 13)
        before = runner.status()
        self.assertEqual(runner.apply(), before)
        auto = SchemaRunner(self.connection)
        self.assertEqual(auto.profile, 'm1')
        auto.require_current()
        self.assertNotIn('032_managed_libraries', {row['version'] for row in before})
        self.assertTrue(any(row['version'] == '101_m1_native_boundary' for row in before))

    def test_native_repositories_shares_versions_and_storage_keys_are_untouched(self):
        repo = str(uuid4())
        runner = self.runner()
        with self.connection.cursor() as cursor:
            for table in ('Repo', 'RepoInfo', 'RepoOwner', 'RepoStorageId', 'SharedRepo', 'RepoGroup', 'Branch'):
                cursor.execute('CREATE TABLE ' + table + '(repo_id CHAR(36) PRIMARY KEY,value VARCHAR(255)) ENGINE=InnoDB')
                cursor.execute('INSERT INTO ' + table + ' VALUES(%s,%s)', (repo, table + '-original'))
            cursor.execute('CREATE TABLE cf_library_storage_key(repo_key VARCHAR(80) PRIMARY KEY,repo_id CHAR(36) UNIQUE) ENGINE=InnoDB')
            cursor.execute('INSERT INTO cf_library_storage_key VALUES(%s,%s)', ('stable-key', repo))
        runner.apply()
        runner.apply()
        for table in ('Repo', 'RepoInfo', 'RepoOwner', 'RepoStorageId', 'SharedRepo', 'RepoGroup', 'Branch'):
            self.assertEqual(runner._query('SELECT * FROM ' + table), ((repo, table + '-original'),))
        self.assertEqual(runner._query('SELECT * FROM cf_library_storage_key'), (('stable-key', repo),))

    def test_legacy_configuration_is_not_migrated_or_erased(self):
        with self.connection.cursor() as cursor:
            cursor.execute('CREATE TABLE cf_dir_admin(id INT PRIMARY KEY)')
            cursor.execute('INSERT INTO cf_dir_admin VALUES(7)')
        runner = self.runner()
        with self.assertRaises(MigrationError):
            runner.apply()
        self.assertEqual(runner._query('SELECT * FROM cf_dir_admin'), ((7,),))
        self.assertFalse(runner._exists())

    def test_interrupted_ddl_resumes_without_replaying_an_existing_table(self):
        runner = self.runner()
        original = runner._apply_one
        def interrupted(migration, previous):
            if migration.version == '006_group_maps':
                raise MigrationError('fixture interruption')
            return original(migration, previous)
        runner._apply_one = interrupted
        with self.assertRaises(MigrationError):
            runner.apply()
        auto = SchemaRunner(self.connection)
        self.assertEqual(auto.profile, 'm1')
        with self.assertRaises(MigrationError):
            auto.require_current()
        auto.apply()
        auto.require_current()

    def test_drift_or_foreign_ledger_versions_cannot_become_ready(self):
        runner = self.runner()
        runner.apply()
        with self.connection.cursor() as cursor:
            cursor.execute('ALTER TABLE cf_dir_acl DROP INDEX acl_shared_recipient')
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection).require_current()
        # Repair is explicit; a matching column alone is never a ready schema.
        with self.connection.cursor() as cursor:
            cursor.execute('ALTER TABLE cf_dir_acl ADD KEY acl_shared_recipient(subject_hash,share_mode,repo_id,path_hash)')
            cursor.execute("UPDATE cf_schema_migration SET checksum=REPEAT('0',64) WHERE version='101_m1_native_boundary'")
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection).require_current()

    def test_acl_publication_audit_and_boundary_need_no_directory_admin_table(self):
        from cloudfile_extensions.authorization.rules import ACLRules
        from cloudfile_extensions.authorization.directory_management import DirectoryAdminRules
        from cloudfile_extensions.resources.store import ResourceEvidence
        self.runner().apply()
        repo = str(uuid4())
        ref = dict(repo_id=repo, path='/project', kind='dir')
        rules = ACLRules(self.connection, provider='directory', actor='manager', request_id='m1-acl', authorize=lambda *args: True,
                         lifecycle_reader=lambda *args: ResourceEvidence('m1-directory-birth'))
        value = dict(path='/project', kind='dir', permission='r', inherit=True, share_mode=1,
                     subject=dict(type='user', provider='directory', namespace='user', external_id='u1'))
        created = rules.mutate(ref, value=value, idempotency_key='m1-create')
        self.assertEqual(rules.mutate(ref, value=value, idempotency_key='m1-create'), created)
        self.assertEqual(rules.candidates(ref)[0]['share_mode'], 1)
        self.assertEqual(self.runner()._query('SELECT repo_id FROM cf_managed_library'), ((repo,),))
        self.assertEqual(self.runner()._query('SELECT COUNT(*) FROM cf_audit_event'), ((1,),))
        rules.mutate(ref, rule_id=created['id'], if_match=created['etag'])
        self.assertEqual(rules.candidates(ref), [])
        # Removing the last rule does not remove the native bypass boundary.
        self.assertEqual(self.runner()._query('SELECT repo_id FROM cf_managed_library'), ((repo,),))
        with self.assertRaises(ContractError) as caught:
            DirectoryAdminRules(self.connection, provider='directory', actor='manager', request_id='m1-admin', authorize=lambda *args: True)
        self.assertEqual(caught.exception.status, 410)

    @unittest.skipUnless(os.environ.get('CF_TEST_REDIS_PORT'), 'requires isolated Redis')
    def test_identity_jit_projection_and_oidc_sessions_use_the_reduced_schema(self):
        import redis
        from cloudfile_extensions.directory.provider import DirectoryProvider
        from cloudfile_extensions.identity.runtime import LoginRuntime
        from cloudfile_extensions.identity.oidc import OIDCConfig
        self.runner().apply()
        native, identity = 'cf_m1_native_' + uuid4().hex, 'cf_m1_identity_' + uuid4().hex
        client = redis.Redis(host='127.0.0.1', port=int(os.environ['CF_TEST_REDIS_PORT']))
        runtime = None
        prefix = 'cf:test:' + uuid4().hex + ':'
        try:
            with self.admin.cursor() as cursor:
                cursor.execute('CREATE DATABASE ' + native)
                cursor.execute('CREATE DATABASE ' + identity)
                cursor.execute('CREATE TABLE ' + native + '.EmailUser(email VARCHAR(255) UNIQUE,passwd VARCHAR(256),is_staff INT,is_active INT,ctime BIGINT) ENGINE=InnoDB')
                cursor.execute('CREATE TABLE ' + native + '.`Group`(group_id INT PRIMARY KEY,parent_group_id INT) ENGINE=InnoDB')
                cursor.execute('INSERT INTO ' + native + '.`Group` VALUES(1,0),(2,0)')
                cursor.execute('CREATE TABLE ' + native + '.GroupUser(group_id INT,user_name VARCHAR(255),is_staff INT,UNIQUE KEY member(group_id,user_name)) ENGINE=InnoDB')
                cursor.execute('CREATE TABLE ' + identity + '.profile_profile(user VARCHAR(254) UNIQUE,login_id VARCHAR(225) UNIQUE,nickname VARCHAR(64),intro TEXT,lang_code TEXT,contact_email VARCHAR(225) UNIQUE,is_manually_set_contact_email TINYINT,institution VARCHAR(225),list_in_address_book TINYINT) ENGINE=InnoDB')
                cursor.execute('CREATE TABLE ' + identity + '.social_auth_usersocialauth(username VARCHAR(255),provider VARCHAR(32),uid VARCHAR(255),extra_data TEXT,UNIQUE KEY binding(provider,uid)) ENGINE=InnoDB')
            with self.connection.cursor() as cursor:
                cursor.execute("INSERT INTO cf_sso_group_map(provider,subject_type,namespace,external_id,group_id,name) VALUES('directory','group','role','r1',1,'Role')")
            transport = Mock()
            transport.get.return_value = dict(userId='u1', status='active', attributes={'login_name': 'E001'}, organizations=[], organization_ancestors=[], roles=[dict(namespace='role', external_id='r1')], etag='one', generated_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'))
            directory = DirectoryProvider('https://directory.example.test/v2', authorization=lambda: 'Bearer fixture', attribute_allowlist={'login_name'}, client=transport, require_organization_ancestors=True)
            oidc = OIDCConfig('https://idp.test/', 'files', 'test-secret', 'https://files.test/callback/', 'https://idp.test/authorize/', 'https://idp.test/token/', 'https://idp.test/userinfo/', 'https://idp.test/jwks/')
            runtime = LoginRuntime(self.connection, client, oidc=oidc, directory=directory, provider_id='directory', native_schema=native, identity_schema=identity, request_id='m1-jit', jit_enabled=True, prefix=prefix)
            claims = dict(issuer=oidc.issuer, sub='stable', userId='u1', login_name='E001')
            username = runtime.jit.ensure(claims)
            preparation = runtime.preparation('u1')
            self.assertEqual(preparation.prepare('u1', trigger='login')['status'], 'ready')
            from datetime import timedelta
            import time
            from cloudfile_extensions.identity.session_index import OIDCSessionIndex
            index = OIDCSessionIndex(self.connection, issuer=oidc.issuer, client_id=oidc.client_id)
            self.connection.begin()
            with self.connection.cursor() as cursor:
                index.register(cursor, session_key='a' * 32, subject='stable', session_id=None,
                               authenticated_at=int(time.time()), expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
            self.connection.commit()
            self.assertEqual(self.runner()._query('SELECT COUNT(*) FROM cf_oidc_session'), ((1,),))
            with self.admin.cursor() as cursor:
                cursor.execute('SELECT group_id,user_name FROM ' + native + '.GroupUser')
                self.assertEqual(cursor.fetchall(), ((1, username),))
                cursor.execute('INSERT INTO ' + native + '.GroupUser VALUES(2,%s,1)', (username,))
            transport.get.return_value.update(status='disabled', roles=[])
            with self.assertRaises(ContractError):
                preparation.prepare('u1', trigger='force')
            with self.admin.cursor() as cursor:
                cursor.execute('SELECT group_id,is_staff FROM ' + native + '.GroupUser')
                self.assertEqual(cursor.fetchall(), ((2, 1),))
        finally:
            if runtime is not None:
                runtime.close()
            keys = list(client.scan_iter(match=prefix + '*'))
            if keys: client.delete(*keys)
            client.close()
            with self.admin.cursor() as cursor:
                cursor.execute('DROP DATABASE IF EXISTS ' + native)
                cursor.execute('DROP DATABASE IF EXISTS ' + identity)
