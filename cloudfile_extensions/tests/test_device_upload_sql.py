"""Real isolated MariaDB against SQL extracted from the native C implementation.

This is transaction/proof regression evidence, not a running seaf-server E2E.
"""
import ast
from contextlib import contextmanager
import hashlib
import json
import os
import re
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.agent_runtime import AgentClaimRuntime
from cloudfile_extensions.local_edit.device_proof import DevicePublicKey
from cloudfile_extensions.local_edit.device_store import DeviceStore
from cloudfile_extensions.local_edit.session_store import LocalSessionStore
from cloudfile_extensions.tests.editing_sql import WORKSPACE
from cloudfile_extensions.tests import test_editing_core as editing_fixture
from cloudfile_extensions.tests.test_schema import DatabaseTestCase
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.editing.store import EditingStore
from cloudfile_extensions.tests import test_device_store as device_fixture
encode = device_fixture.encode


def native_sql(prefix):
    source = (WORKSPACE / 'cloudfile-server/server/cloudfile-policy.c').read_text()
    queries = []
    for group in re.findall(r'(?:"(?:[^"\\]|\\.)*"\s*)+', source):
        value = ''.join(ast.literal_eval(x) for x in re.findall(r'"(?:[^"\\]|\\.)*"', group))
        if value.startswith(prefix):
            queries.append(value)
    if len(queries) != 1:
        raise ValueError('one actual native predicate required: ' + prefix)
    return queries[0].replace('?', '%s')


class DeviceUploadSQLTests(DatabaseTestCase):
    transaction = editing_fixture.EditingCoreTest.transaction
    acquire = editing_fixture.EditingCoreTest.acquire
    proof = editing_fixture.EditingCoreTest.proof
    native_publish = editing_fixture.EditingCoreTest.native_publish

    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = EditingStore()
        self.target = dict(uid=str(uuid4()), repo=str(uuid4()), lifecycle='fixture')
        self.path = '/folder/a.docx'
        self.identity = dict(actor='employee', holder='device', token='a' * 64)
        with self.connection.cursor() as sql:
            sql.execute('CREATE TABLE fixture_content(repo CHAR(36) PRIMARY KEY,file_id CHAR(40)) ENGINE=InnoDB')
            sql.execute('INSERT INTO fixture_content VALUES(%s,%s)', (self.target['repo'], 'b' * 40))
            sql.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) VALUES(%s,%s,'file',%s,%s,%s,1,'active',UTC_TIMESTAMP(6))",
                (self.target['uid'], self.target['repo'], self.path,
                 hashlib.sha256(self.path.encode()).hexdigest(), self.target['lifecycle']))
        self.private = ec.generate_private_key(ec.SECP256R1())
        public = self.private.public_key().public_numbers()
        key = DevicePublicKey.parse(dict(kty='EC', crv='P-256',
            x=encode(public.x.to_bytes(32, 'big')), y=encode(public.y.to_bytes(32, 'big'))))
        self.device_id = str(uuid4())
        self.owner = dict(provider='etech', actor=self.identity['actor'], device_id=self.device_id)
        devices = DeviceStore()
        self.sessions = LocalSessionStore()
        with self.transaction() as sql:
            devices.create_pending(sql, **self.owner, public_key=key)
            c = devices.issue(sql, **self.owner, instance='https://cloudfile.invalid',
                session_id=str(uuid4()), operation='pair', request_sha256='a' * 64)
            devices.consume(sql, provider='etech', actor=self.identity['actor'], challenge=c, signature=self.sign(c))
            self.guard = self.acquire(sql)
            self.edit_proof = self.proof(self.guard)
            snapshot = dict(resource=dict(repo_id=self.target['repo'], path=self.path, kind='file'),
                resource_uid=self.target['uid'], lifecycle_ref=self.target['lifecycle'],
                base_version='b' * 40, resource_revision='1', local_open_type='', mode='exclusive-edit',
                lease=dict(fencing=self.guard['generation'], token_digest=hashlib.sha256(self.identity['token'].encode()).hexdigest()))
            issued = self.sessions.create(sql, **self.owner, snapshot=snapshot)
            self.session_id = issued.session_id
            args = dict(**self.owner, session_id=self.session_id, ticket=issued.ticket,
                current_snapshot=snapshot, instance='https://cloudfile.invalid')
            c = self.sessions.challenge(sql, **args)
            self.sessions.claim(sql, **args, challenge=c, signature=self.sign(c))
            self.original = self.device_prepare(sql)
        @contextmanager
        def connection():
            yield self.connection
        self.runtime = object.__new__(AgentClaimRuntime)
        self.runtime.pid = os.getpid()
        self.runtime.agent2_exclusive_enabled = True
        self.runtime.resources = SimpleNamespace(provider='etech', connection=connection)
        self.runtime.instance = 'https://cloudfile.invalid'
        self.runtime.sessions = self.sessions

    sign = device_fixture.DeviceStoreTests.sign

    def device_prepare(self, sql, action='commit', base='b'):
        intent = str(uuid4())
        return self.store.prepare(sql, **self.target, **self.edit_proof, intent_id=intent,
            expected_file_id=base * 40, staged_file_id=None, content_digest='e' * 64, action=action,
            snapshot=dict(id=intent, size=0, source='agent2-device',
                session_id=self.session_id, device_id=self.device_id))

    def status(self, intent=None):
        body = dict(session_id=self.session_id, device_id=self.device_id,
            intent_id=intent or self.original['intent_id'])
        challenge = self.runtime.commit_status_challenge(body, 'fixture-request')['challenge']
        from cloudfile_extensions.local_edit.device_proof import DeviceChallenge
        return self.runtime.commit_status(dict(body, challenge=challenge,
            signature=self.sign(DeviceChallenge(**challenge))), 'fixture-request')['intent']

    def test_native_session_schema_gates_match_real_migration_ledger(self):
        with self.transaction() as sql:
            for version in ('030_local_devices', '031_edit_sessions'):
                query = native_sql("SELECT version FROM cf_schema_migration WHERE version='" + version + "'")
                sql.execute(query)
                self.assertEqual(sql.fetchall(), ((version,),))
                sql.execute("SAVEPOINT migration_gate")
                sql.execute("UPDATE cf_schema_migration SET state='applying' WHERE version=%s", (version,))
                sql.execute(query)
                self.assertEqual(sql.fetchall(), ())
                sql.execute("ROLLBACK TO SAVEPOINT migration_gate")

    def test_device_native_predicates_shared_cases(self):
        cases = json.loads((WORKSPACE / 'cloudfile-docker/docs/device-edit-upload-cases.json').read_text())
        session_query = native_sql('SELECT s.snapshot,r.uid,r.lifecycle_ref,COALESCE')
        lease_query = native_sql('SELECT resource_uid FROM cf_edit_guard WHERE resource_uid=')
        intent_query = native_sql('SELECT intent_id FROM cf_commit_intent WHERE intent_id=?')
        with self.transaction() as sql:
            for case in cases:
                sql.execute('SAVEPOINT predicate_case')
                if case['mutation']:
                    sql.execute(case['mutation'])
                sql.execute(session_query, (self.target['repo'], hashlib.sha256(self.path.encode()).hexdigest(), self.path,
                    self.session_id, 'etech', self.identity['actor'], self.device_id, '2', '2'))
                session_ok = len(sql.fetchall()) == 1
                sql.execute(lease_query, (self.target['uid'], self.target['repo'], self.target['lifecycle'],
                    self.identity['actor'], self.guard['generation'], hashlib.sha256(self.identity['token'].encode()).hexdigest(), 'b' * 40))
                lease_ok = len(sql.fetchall()) == 1
                sql.execute(intent_query, (self.original['intent_id'], self.session_id, self.device_id))
                intent_ok = len(sql.fetchall()) == 1
                self.assertEqual(session_ok and lease_ok and intent_ok, case['allowed'], case['name'])
                sql.execute('ROLLBACK TO SAVEPOINT predicate_case')

    def test_commit_and_checkin_advance_session_with_receipt_and_recover(self):
        self.assertEqual(self.status()['state'], 'prepared')
        update = native_sql('UPDATE cf_edit_session SET snapshot=JSON_SET')
        with self.transaction() as sql:
            self.native_publish(sql, self.edit_proof, self.original['intent_id'])
            sql.execute(update, ('c' * 40, 'active', self.session_id))
        self.assertEqual(self.status()['state'], 'published')
        with self.transaction() as sql:
            sql.execute('SELECT snapshot,revision,state FROM cf_edit_session WHERE session_id=%s', (self.session_id,))
            snapshot, revision, state = sql.fetchone()
            self.assertEqual((json.loads(snapshot)['base_version'], revision, state), ('c' * 40, 3, 'active'))
            ready = self.sessions._read_ready(sql, **self.owner, session_id=self.session_id,
                current_snapshot=json.loads(snapshot))
            self.assertEqual(ready[9], 3)
            final = self.device_prepare(sql, action='checkin', base='c')
            self.native_publish(sql, self.edit_proof, final['intent_id'])
            sql.execute(update, ('c' * 40, 'completed', self.session_id))
        # Completed session and released guard must not prevent lost-reply recovery.
        self.assertTrue(self.status(final['intent_id'])['checked_in'])
        self.assertEqual(self.status()['state'], 'published')

    def test_status_proof_not_reusable_or_interchangeable(self):
        body = dict(session_id=self.session_id, device_id=self.device_id, intent_id=self.original['intent_id'])
        c = self.runtime.commit_status_challenge(body, 'request')['challenge']
        from cloudfile_extensions.local_edit.device_proof import DeviceChallenge
        signed = dict(body, challenge=c, signature=self.sign(DeviceChallenge(**c)))
        self.assertEqual(self.runtime.commit_status(signed, 'request')['intent']['state'], 'prepared')
        with self.assertRaises(ContractError):
            self.runtime.commit_status(signed, 'request')
        with self.transaction() as sql:
            sql.execute("UPDATE cf_local_device SET state='revoked' WHERE device_id=%s", (self.device_id,))
        with self.assertRaises(ContractError):
            self.status()

    def test_receipt_does_not_cross_session_and_absent_is_not_success(self):
        self.assertEqual(self.status(str(uuid4()))['state'], 'not-found')
        with self.transaction() as sql:
            sql.execute("UPDATE cf_commit_intent SET snapshot=JSON_SET(snapshot,'$.session_id',%s) WHERE intent_id=%s",
                (str(uuid4()), self.original['intent_id']))
        with self.assertRaises(ContractError):
            self.status()

    def test_publication_and_session_advance_rollback_together(self):
        with self.assertRaises(RuntimeError):
            with self.transaction() as sql:
                self.native_publish(sql, self.edit_proof, self.original['intent_id'])
                sql.execute(native_sql('UPDATE cf_edit_session SET snapshot=JSON_SET'),
                    ('c' * 40, 'active', self.session_id))
                raise RuntimeError('simulate failure before Branch transaction commit')
        self.assertEqual(self.status()['state'], 'prepared')
        with self.transaction() as sql:
            sql.execute('SELECT snapshot,revision FROM cf_edit_session WHERE session_id=%s', (self.session_id,))
            snapshot, revision = sql.fetchone()
            self.assertEqual((json.loads(snapshot)['base_version'], revision), ('b' * 40, 2))
            guard = self.store.load(sql, **self.target)
            self.assertEqual(guard['pending_intent'], self.original['intent_id'])
            self.assertEqual(guard['base_file_id'], 'b' * 40)

    def test_encrypted_checkout_handoff_ack_erases_server_secret(self):
        from cloudfile_extensions.local_edit.lease_escrow import CheckoutLeaseEscrow
        escrow = CheckoutLeaseEscrow()
        secret = b"test-only-cloudfile-server-secret-32bytes"
        lease = dict(guard_id=self.guard["guard_id"],
            generation=str(self.guard["generation"]),
            credential_epoch=str(self.guard["credential_epoch"]),
            base_file_id="b"*40,token=self.identity["token"])
        arguments = dict(instance="https://cloudfile.invalid", session=self.session_id,
            device=self.device_id, actor=self.identity["actor"])
        with self.transaction() as sql:
            escrow.create(sql, secret=secret, lease=lease, **arguments)
            sql.execute("SELECT ciphertext FROM cf_device_checkout_lease WHERE session_id=%s",
                        (self.session_id,))
            encoded = bytes(sql.fetchone()[0])
            self.assertNotIn(lease["token"].encode(), encoded)
            self.assertEqual(escrow.receive(sql, secret=secret, **arguments,
                expected_digest=hashlib.sha256(lease["token"].encode()).hexdigest()),lease)
            escrow.confirm(sql,session=self.session_id)
            sql.execute("SELECT LENGTH(ciphertext),acknowledged_at FROM cf_device_checkout_lease WHERE session_id=%s",
                        (self.session_id,))
            size, acknowledged = sql.fetchone()
            self.assertEqual(size,0)
            self.assertIsNotNone(acknowledged)
            with self.assertRaises(ContractError):
                escrow.receive(sql, secret=secret, **arguments,
                    expected_digest=hashlib.sha256(lease["token"].encode()).hexdigest())

    def test_signed_lease_renewal_respects_existing_guard_expiry(self):
        from datetime import datetime
        with self.transaction() as sql:
            sql.execute("SELECT lease_until FROM cf_edit_guard WHERE resource_uid=%s",
                        (self.target["uid"],))
            original = sql.fetchone()[0]
            sql.execute(
                "UPDATE cf_edit_guard SET lease_until=LEAST(hard_expire_at,"
                "TIMESTAMPADD(SECOND,600,UTC_TIMESTAMP(6))) "
                "WHERE resource_uid=%s AND guard_id=%s AND generation=%s "
                "AND owner=%s AND proof_digest=%s AND mode='checkout' "
                "AND lease_until>UTC_TIMESTAMP(6) AND hard_expire_at>UTC_TIMESTAMP(6)",
                (self.target["uid"], self.guard["guard_id"], self.guard["generation"],
                 self.identity["actor"], hashlib.sha256(self.identity["token"].encode()).hexdigest()))
            self.assertEqual(sql.rowcount,1)
            sql.execute("SELECT lease_until FROM cf_edit_guard WHERE resource_uid=%s",
                        (self.target["uid"],))
            self.assertGreaterEqual(sql.fetchone()[0],original)
            sql.execute(
                "UPDATE cf_edit_session SET expires_at=GREATEST(expires_at,"
                "FLOOR(UNIX_TIMESTAMP())+1800),updated_at=UTC_TIMESTAMP(6) "
                "WHERE session_id=%s AND device_id=%s AND state IN ('claimed','active') "
                "AND expires_at>FLOOR(UNIX_TIMESTAMP())",
                (self.session_id,self.device_id))
            sql.execute("UPDATE cf_edit_guard SET lease_until=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) "
                        "WHERE resource_uid=%s",(self.target["uid"],))
            sql.execute(
                "UPDATE cf_edit_guard SET lease_until=LEAST(hard_expire_at,"
                "TIMESTAMPADD(SECOND,600,UTC_TIMESTAMP(6))) "
                "WHERE resource_uid=%s AND guard_id=%s AND generation=%s "
                "AND owner=%s AND proof_digest=%s AND mode='checkout' "
                "AND lease_until>UTC_TIMESTAMP(6) AND hard_expire_at>UTC_TIMESTAMP(6)",
                (self.target["uid"], self.guard["guard_id"], self.guard["generation"],
                 self.identity["actor"], hashlib.sha256(self.identity["token"].encode()).hexdigest()))
            self.assertEqual(sql.rowcount,0)
