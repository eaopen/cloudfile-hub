"""Annotations through real MariaDB transactions, locks, candidates and C.

Subject delivery and native lifecycle are fixtures; this does not claim native
RPC/session integration. Use an isolated CF_TEST_DB_PORT and compiled C core.
"""
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from cloudfile_extensions.authorization.core import PolicyCore
from cloudfile_extensions.authorization.rules import ACLRules
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.native_state import NativeSubjectState
from cloudfile_extensions.directory.preparation import SubjectPreparation
from cloudfile_extensions.jobs.authority import canonical_scope, lock_name
from cloudfile_extensions.resources.service import ResourceService
from cloudfile_extensions.resources.store import ResourceEvidence
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tags.write import create_user
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


@unittest.skipUnless(os.environ.get('CF_TEST_ACL_LIBRARY'), 'requires compiled shared C policy core')
class ResourceBatchSQLTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        with self.connection.cursor() as cursor:
            for sql in (
                'CREATE TABLE EmailUser(email VARCHAR(255) PRIMARY KEY,is_active TINYINT,is_staff TINYINT) ENGINE=InnoDB',
                'CREATE TABLE profile_profile(user VARCHAR(255) PRIMARY KEY,login_id VARCHAR(225) UNIQUE) ENGINE=InnoDB',
                'CREATE TABLE Repo(repo_id CHAR(36) PRIMARY KEY) ENGINE=InnoDB',
                'CREATE TABLE RepoInfo(repo_id CHAR(36) PRIMARY KEY,status INT) ENGINE=InnoDB',
                'CREATE TABLE RepoOwner(repo_id CHAR(36) PRIMARY KEY,owner_id VARCHAR(255)) ENGINE=InnoDB',
                'CREATE TABLE VirtualRepo(repo_id CHAR(36) PRIMARY KEY) ENGINE=InnoDB',
                'CREATE TABLE cf_test_reader_effect(value INT) ENGINE=InnoDB'):
                cursor.execute(sql)
            cursor.execute("INSERT INTO EmailUser VALUES('native-user',1,0)")
            cursor.execute("INSERT INTO profile_profile VALUES('native-user','employee')")
        self.preparation = object.__new__(SubjectPreparation)
        self.preparation.actor = 'employee'
        self.preparation._read_epoch = None
        self.preparation.projector = SimpleNamespace(native_table='Group')
        self.preparation.state = NativeSubjectState(self.connection, native_schema=self.database,
            identity_schema=self.database, provider='directory')
        self.context = dict(context_epoch='epoch', subject=dict(userId='employee', status='active', attributes={},
            organizations=[], roles=[], etag='current',
            generated_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')))
        self.preparation.contexts = SimpleNamespace(allowlist=(), get=Mock(return_value=self.context),
            current=Mock(side_effect=lambda actor: self.context))
        self.core = PolicyCore(os.environ['CF_TEST_ACL_LIBRARY'])
        self.core.evaluate = Mock(wraps=self.core.evaluate)
        self.lifecycle = Mock(return_value=ResourceEvidence('birth'))
        self.service = ResourceService(self.preparation, self.core, cloud_mode=False, request_id='batch-sql-test',
            secret=b'batch-test-secret-at-least-32-bytes', lifecycle_reader=self.lifecycle)
        self.rules = ACLRules(self.connection, provider='directory', actor='fixture', request_id='batch-fixture',
            authorize=lambda *args: True)

    def references(self, count):
        repo = str(uuid4())
        with self.connection.cursor() as cursor:
            cursor.execute('INSERT INTO Repo VALUES(%s)', (repo,))
            cursor.execute('INSERT INTO RepoInfo VALUES(%s,0)', (repo,))
            cursor.execute("INSERT INTO RepoOwner VALUES(%s,'native-user')", (repo,))
        return [dict(repo_id=repo, path='/folder/item-' + str(index), kind='file') for index in range(count)]

    def rule(self, ref, permission, inherit=False):
        self.rules.mutate(ref, value=dict(path=ref['path'], kind=ref['kind'], permission=permission,
            inherit=inherit, subject=dict(type='user', provider='directory', namespace='user', external_id='employee')))

    def test_real_c_inheritance_file_deny_metadata_and_single_parity(self):
        refs = self.references(21)
        other = self.references(1)[0]
        self.rule({**refs[0], 'path': '/folder', 'kind': 'dir'}, 'r', True)
        self.rule(refs[0], 'none')
        self.rule(refs[20], 'invisible')
        # Annotated item and unannotated native objects use the same API. The
        # sparse identity belongs to its lifecycle, never allocated by a read.
        resource = str(uuid4())
        self.connection.begin()
        with self.connection.cursor() as cursor:
            cursor.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) "
                "VALUES(%s,%s,'file',%s,%s,'birth',1,'active',UTC_TIMESTAMP(6))", (resource, refs[1]['repo_id'],
                refs[1]['path'], self.service.store._hash(refs[1]['path'])))
            tag, _ = create_user(cursor, repo_id=refs[1]['repo_id'], value=dict(label='Drawing'),
                actor='employee', request_id='batch-fixture')
            cursor.execute('INSERT INTO cf_tag_binding(resource_uid,tag_id) VALUES(%s,%s)', (resource, tag['tag_id']))
        self.connection.commit()
        requested = [other, *refs, refs[1]]
        result = self.service.batch_resolve(dict(references=requested))['items']
        self.assertEqual(self.core.evaluate.call_count, 22)
        self.assertEqual(self.lifecycle.call_count, 20)
        self.assertEqual([item['reference'] for item in result], requested)
        self.assertEqual(result[1]['status'], 404)
        self.assertEqual(result[-2]['status'], 404)
        self.assertEqual(result[2]['snapshot']['access'], dict(read=True, write=False))
        self.assertEqual(result[0]['snapshot']['access'], dict(read=True, write=True))
        self.assertEqual(result[2]['snapshot']['tags'], [tag])
        self.assertEqual(result[2], result[-1])
        for index in (0, 2, 3):
            self.assertEqual(result[index]['snapshot'], self.service.resolve(dict(reference=requested[index])))
        with self.assertRaises(ContractError) as caught:
            self.service.resolve(dict(reference=refs[0]))
        self.assertEqual(caught.exception.status, 403)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_resource')
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_reader_effect_rolls_back_when_final_epoch_check_fails(self):
        refs = self.references(1)
        name = lock_name(self.database, canonical_scope(dict(type='repo', provider='cloudfile',
            external_id=refs[0]['repo_id'])))
        def reader(cursor, targets, accesses):
            cursor.execute('SELECT IS_USED_LOCK(%s)=CONNECTION_ID()', (name,))
            self.assertEqual(cursor.fetchone()[0], 1)
            cursor.execute('INSERT INTO cf_test_reader_effect VALUES(1)')
            self.context = {**self.context, 'context_epoch': 'changed'}
            return ['must-not-escape']
        with self.assertRaises(ContractError) as caught:
            self.service.read_authority.consume_many(refs, reader=reader)
        self.assertEqual(caught.exception.code, 'SUBJECT_UNAVAILABLE')
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_test_reader_effect')
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute('SELECT IS_FREE_LOCK(%s)', (name,))
            self.assertEqual(cursor.fetchone()[0], 1)
        self.assertIsNone(self.service.read_authority.current_subject)

    def test_real_sql_100_items_and_all_deny(self):
        refs = self.references(100)
        result = self.service.batch_resolve(dict(references=refs))['items']
        self.assertEqual(len(result), 100)
        self.assertEqual(self.core.evaluate.call_count, 100)
        self.assertTrue(all(item['status'] == 200 and item['snapshot']['uid'] is None for item in result))
        self.rule({**refs[0], 'path': '/folder', 'kind': 'dir'}, 'invisible', True)
        self.lifecycle.reset_mock()
        result = self.service.batch_resolve(dict(references=refs))['items']
        self.assertTrue(all(item['status'] == 404 for item in result))
        self.lifecycle.assert_not_called()
