"""Live SQL audit persistence and failed append rollback, not native receipts."""
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4
import json

from cloudfile_extensions.identity.transfer_audit import record_transfer, audit_peer_ip
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class TransferAuditTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        @contextmanager
        def owned():
            yield self.connection
        self.resources = SimpleNamespace(connection=owned)
        self.reference = dict(repo_id=str(uuid4()), path='/part.txt', kind='file')

    def test_attempt_and_confirmed_success_keep_business_identity_and_version(self):
        record_transfer(self.resources, 'business-user', self.reference, 'request', 'file.update', 'attempted')
        record_transfer(self.resources, 'business-user', self.reference, 'request', 'file.update', 'succeeded',
            reason='NATIVE_COMPLETION_ACKNOWLEDGED', content_version='a' * 40, client_ip='192.0.2.10')
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT event_payload,client_ip FROM cf_audit_event ORDER BY id')
            records = cursor.fetchall()
            facts = [json.loads(row[0]) for row in records]
        self.assertEqual([f['result'] for f in facts], ['attempted', 'succeeded'])
        self.assertTrue(all(f['actor_user_id'] == 'business-user' and f['source'] == 'hub'
            and f['path'] == '/part.txt' and f['occurred_at'] for f in facts))
        self.assertEqual(facts[-1]['content_version'], 'a' * 40)
        self.assertEqual(records[-1][1], '192.0.2.10')

    def test_peer_ip_ignores_untrusted_forwarding(self):
        request = SimpleNamespace(META={'REMOTE_ADDR': '192.0.2.10', 'HTTP_X_FORWARDED_FOR': '203.0.113.5'})
        self.assertEqual(audit_peer_ip(request), '192.0.2.10')
        request.META['REMOTE_ADDR'] = 'invalid'
        self.assertIsNone(audit_peer_ip(request))

    def test_denial_and_unknown_completion_cannot_be_success(self):
        for result, reason in [('denied', 'ACCESS_DENIED'), ('interrupted', 'PUBLICATION_UNCONFIRMED')]:
            saved = record_transfer(self.resources, 'business-user', self.reference, result, 'file.upload', result, reason=reason)
            self.assertEqual(saved['result'], result)
            self.assertNotIn('content_version', saved)

    def test_failed_audit_append_rolls_back_partial_fact(self):
        from cloudfile_extensions.events.outbox import EventWriter
        real = EventWriter.append
        def fail(writer, cursor, fact):
            real(writer, cursor, fact)
            raise RuntimeError('fixture storage failure')
        with patch.object(EventWriter, 'append', fail):
            with self.assertRaises(ContractError) as error:
                record_transfer(self.resources, 'business-user', self.reference, 'failure', 'file.upload', 'attempted')
        self.assertEqual(error.exception.code, 'AUDIT_UNAVAILABLE')
        with self.connection.cursor() as cursor:
            for table in ('cf_audit_event', 'cf_event_outbox'):
                cursor.execute('SELECT COUNT(*) FROM ' + table)
                self.assertEqual(cursor.fetchone()[0], 0)

    def test_existing_policy_mutations_record_actor_action_resource_time_result(self):
        from cloudfile_extensions.authorization.rules import ACLRules
        rules = ACLRules(self.connection, provider='etech', actor='policy-manager', request_id='policy',
            authorize=lambda cursor, actor, reference: True)
        reference = dict(self.reference, path='/', kind='dir')
        value = dict(path='/', kind='dir', permission='r', inherit=False,
            subject=dict(type='user', provider='etech', namespace='user', external_id='business-user'))
        one = rules.mutate(reference, value=value)
        two = rules.mutate(reference, value=dict(value, permission='rw'), rule_id=one['id'], if_match=one['etag'])
        rules.mutate(reference, rule_id=two['id'], if_match=two['etag'])
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT event_payload FROM cf_audit_event ORDER BY id')
            facts = [json.loads(row[0]) for row in cursor.fetchall()]
        self.assertEqual([f['action'] for f in facts], ['acl.created', 'acl.updated', 'acl.deleted'])
        self.assertTrue(all(f['actor_user_id'] == 'policy-manager' and f['result'] == 'succeeded'
            and f['repo_id'] == reference['repo_id'] and f['path'] == '/' and f['occurred_at'] for f in facts))
