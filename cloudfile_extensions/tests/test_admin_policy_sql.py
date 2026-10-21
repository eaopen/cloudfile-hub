"""Real transaction/replay tests for the native system administrator principal."""
from types import SimpleNamespace
from uuid import uuid4

from cloudfile_extensions.authorization.admin_management import SystemAdministratorManagement
from cloudfile_extensions.authorization.share_service import DirectoryShareService
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.store import ResourceEvidence
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AdministratorPolicySQLTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.repo = str(uuid4())
        with self.connection.cursor() as cursor:
            for sql in ('CREATE TABLE EmailUser(email VARCHAR(255) PRIMARY KEY,is_active TINYINT,is_staff TINYINT) ENGINE=InnoDB',
                        'CREATE TABLE Repo(repo_id CHAR(36) PRIMARY KEY) ENGINE=InnoDB',
                        'CREATE TABLE RepoInfo(repo_id CHAR(36) PRIMARY KEY,status INT) ENGINE=InnoDB',
                        'CREATE TABLE VirtualRepo(repo_id CHAR(36) PRIMARY KEY) ENGINE=InnoDB',
                        'CREATE TABLE RepoOwner(repo_id CHAR(36) PRIMARY KEY,owner_id VARCHAR(255)) ENGINE=InnoDB'):
                cursor.execute(sql)
            cursor.execute("INSERT INTO EmailUser VALUES('cfadmin@fixture',1,1)")
            cursor.execute('INSERT INTO Repo VALUES(%s)', (self.repo,))
            cursor.execute('INSERT INTO RepoInfo VALUES(%s,0)', (self.repo,))
            cursor.execute("INSERT INTO RepoOwner VALUES(%s,'original-owner')", (self.repo,))
        self.reference = dict(repo_id=self.repo, path='/folder', kind='dir')
        self.resources = SimpleNamespace(native_schema=self.database, identity_schema=self.database, provider='etech')
        self.authority = SystemAdministratorManagement(self.resources, self.connection,
            username='cfadmin@fixture', reference=self.reference, request_id='administrator-test',
            authorize_library=lambda ref: True, lifecycle_reader=lambda *args: ResourceEvidence('fixture:birth'))
        self.value = dict(path='/folder', kind='dir', permission='rw', inherit=True,
            subject=dict(type='user', provider='etech', namespace='user', external_id='business-uid'))

    def test_acl_replay_shared_record_and_conditional_revoke(self):
        rules = self.authority.rules
        first = rules.mutate(self.reference, value=self.value, idempotency_key='acl-create')
        self.assertEqual(rules.mutate(self.reference, value=self.value, idempotency_key='acl-create'), first)
        shares = DirectoryShareService(self.authority, lifecycle_reader=rules.lifecycle_reader)
        shared = shares.create(dict(reference=self.reference, value=dict(path='/folder', subject=self.value['subject'])),
                               idempotency_key='share-create')
        self.assertEqual(shared['id'], first['id'])
        self.assertEqual(shared['permission'], 'rw')
        self.assertEqual(shares.list(dict(reference=self.reference))['items'][0]['share_mode'], 1)
        shares.delete(shared['id'], dict(reference=self.reference), if_match=shared['etag'], idempotency_key='share-delete')
        current = rules.list_target(self.reference)['items'][0]
        self.assertEqual(current['share_mode'], 0)
        self.assertEqual(current['permission'], 'rw')
        with self.assertRaises(ContractError) as error:
            rules.mutate(self.reference, value={**self.value, 'permission':'r'}, rule_id=first['id'], if_match=first['etag'])
        self.assertEqual(error.exception.status, 412)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT payload FROM cf_event_outbox')
            events = cursor.fetchall()
        import json
        self.assertTrue(events)
        for payload, in events:
            event = json.loads(payload)
            self.assertEqual(event['actor_kind'], 'service')
            self.assertEqual(event['actor_user_id'], 'native-account:cfadmin@fixture')
        rules.mutate(self.reference, rule_id=current['id'], if_match=current['etag'], idempotency_key='acl-delete')
        self.assertEqual(rules.list_library(self.repo)['items'], [])

    def test_disabled_or_demoted_account_cannot_replay_or_write(self):
        rules = self.authority.rules
        rules.mutate(self.reference, value=self.value, idempotency_key='recorded')
        for column in ('is_active', 'is_staff'):
            with self.connection.cursor() as cursor:
                cursor.execute('UPDATE EmailUser SET ' + column + '=0')
            with self.assertRaises(ContractError) as error:
                rules.mutate(self.reference, value=self.value, idempotency_key='recorded')
            self.assertEqual(error.exception.status, 403)
            with self.connection.cursor() as cursor:
                cursor.execute('UPDATE EmailUser SET ' + column + '=1')

    def test_cross_library_and_virtual_library_are_rejected_without_writes(self):
        rules = self.authority.rules
        with self.assertRaises(ContractError):
            rules.mutate({**self.reference, 'repo_id':str(uuid4())}, value=self.value)
        with self.connection.cursor() as cursor:
            cursor.execute('INSERT INTO VirtualRepo VALUES(%s)', (self.repo,))
        with self.assertRaises(ContractError):
            rules.mutate(self.reference, value=self.value)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_dir_acl')
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_final_authority_failure_rolls_back_acl_event_and_retry_record(self):
        calls = []
        def changed(ref):
            calls.append(ref)
            return len(calls) == 1
        self.authority.authorize_library = changed
        with self.assertRaises(ContractError):
            self.authority.rules.mutate(self.reference, value=self.value, idempotency_key='rolled-back')
        with self.connection.cursor() as cursor:
            for table in ('cf_dir_acl', 'cf_event_outbox', 'cf_policy_request'):
                cursor.execute('SELECT COUNT(*) FROM ' + table)
                self.assertEqual(cursor.fetchone()[0], 0)
