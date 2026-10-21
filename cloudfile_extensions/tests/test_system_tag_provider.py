"""Provider JWT + real atomic SQL; user/native authority is an explicit fixture."""
import time
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import jwt

from cloudfile_extensions.authorization.read import ContentMetadataWriteAuthority
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.service_tokens import ServiceCredential, ServiceTokenVerifier
from cloudfile_extensions.resources.provider import SystemTagProvider
from cloudfile_extensions.resources.store import ResourceStore, ResourceEvidence
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class SystemTagProviderTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.ref = dict(repo_id=str(uuid4()), path='/file', kind='file')
        self.evidence = ResourceEvidence('fixture-native-birth')
        self.store = ResourceStore(self.connection, inspector=Mock(), write_guard=Mock(),
            secret=b'fixture-secret-at-least-32-bytes-long', mutation_hook=Mock())
        self.authority = Mock(spec=ContentMetadataWriteAuthority)
        self.authority.actor = 'fixture-user'
        self.authority.state = Mock(connection=self.connection, provider='etech')
        self.authority.consume.side_effect = self.consume
        self.service = SimpleNamespace(store=self.store, write_authority=self.authority,
            reader=lambda cursor, ref: self.evidence, request_id='provider-fixture')
        self.secret = b'fixture-provider-secret-at-least-32-bytes'
        self.verifier = ServiceTokenVerifier({'tags': ServiceCredential('etech-tags', 'etech-tags',
            'cloudfile-tags', self.secret, frozenset({'tags.system.write', 'other.read'}))})
        self.provider = SystemTagProvider(self.verifier, {'etech-tags': dict(provider='etech',
            namespaces=['etech:project', 'etech:stage'])})
        self.initial = self.store._snapshot(self.ref, self.evidence, None)['revision']

    def consume(self, ref, callback):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                result = callback(cursor, ref)
            self.connection.commit()
            return result
        finally:
            self.connection.rollback()

    def token(self, scope='tags.system.write'):
        now = int(time.time())
        return 'Bearer ' + jwt.encode(dict(iss='etech-tags', aud='cloudfile-tags', sub='etech-tags',
            iat=now, exp=now + 60, jti=str(uuid4()), scope=scope), self.secret, algorithm='HS256', headers={'kid': 'tags'})

    def save(self, updates, revision=None, key='save', scope='tags.system.write'):
        return self.provider.replace(self.service, dict(reference=self.ref,
            revision=revision or self.initial, updates=updates), credential=self.token(scope), key=key)

    def count(self, table):
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM ' + table)
            return cursor.fetchone()[0]

    def test_namespace_replacement_preserves_user_and_other_system_tags_and_replays(self):
        user, _ = self.store.replace_user_tags_authorized(self.ref, [], expected_revision=self.initial,
            authority=self.authority, lifecycle_reader=self.service.reader, request_id='fixture',
            tag_values=[dict(label='user-label')], idempotency_key='user-1')
        updates = [dict(namespace='etech:project', values=[dict(code='P1', label='Project 1')]),
            dict(namespace='etech:stage', values=[dict(code='DRAFT', label='Draft')])]
        saved = self.save(updates, user['revision'])
        self.assertEqual({tag['label'] for tag in saved[0]['tags']}, {'Project 1', 'Draft', 'user-label'})
        before = self.count('cf_event_outbox')
        self.assertEqual(self.save(updates, user['revision']), saved)
        self.assertEqual(self.count('cf_event_outbox'), before)
        cleared, _ = self.save([dict(namespace='etech:project', values=[])], saved[0]['revision'], key='clear')
        self.assertEqual({tag['label'] for tag in cleared['tags']}, {'Draft', 'user-label'})

    def test_namespace_and_service_scope_are_checked_before_allocation(self):
        for updates, scope in (([dict(namespace='foreign', values=[])], 'tags.system.write'),
                ([dict(namespace='etech:project', values=[])], 'other.read')):
            with self.assertRaises(ContractError) as raised:
                self.save(updates, scope=scope)
            self.assertEqual(raised.exception.status, 403)
        self.assertEqual(self.count('cf_resource'), 0)
        self.assertEqual(self.count('cf_tag'), 0)

    def test_later_disabled_binding_rolls_back_entire_namespace_batch(self):
        with self.assertRaises(ContractError) as raised:
            self.save([dict(namespace='etech:project', values=[dict(code='P1')]),
                dict(namespace='etech:stage', values=[dict(code='DISABLED', enabled=False)])])
        self.assertEqual(raised.exception.code, 'TAG_DISABLED')
        for table in ('cf_resource', 'cf_tag', 'cf_tag_binding', 'cf_policy_request', 'cf_event_outbox'):
            self.assertEqual(self.count(table), 0)
