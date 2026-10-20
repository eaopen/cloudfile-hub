"""Runtime integration failures never become native membership readiness."""
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from django.test import override_settings

from cloudfile_ext.v2.etech_directory import Directory, prepare_user, prepare_group, ensure_subject
from cloudfile_ext.v2.errors import IdentityUnavailable, IdentityConflict
from cloudfile_ext.v2.identity import NativeIdentity
from cloudfile_ext.v2.tests.native_identity_facts import NativeFacts


def subject(status='active'):
    return dict(userId='uid', status=status, attributes={'employee_no':'E001'},
                organizations=[dict(namespace='directory', external_id='o1')] if status=='active' else [],
                organization_ancestors=[], roles=[], etag='version', generated_at=datetime.now(timezone.utc).isoformat())


class DirectoryRuntimeTests(TestCase):
    @contextmanager
    def runtime(self):
        self.directory, self.identity, self.catalog, self.memberships = (Mock() for _ in range(4))
        self.directory.subject.return_value=subject()
        self.directory.entities.return_value={('org','directory','o1'): {'name': 'Department', 'parent': None}}
        self.identity.prepare.return_value='opaque@auth.local'
        self.catalog.ensure.return_value=42
        yield self.directory, self.identity, self.catalog, self.memberships

    def test_preparation_proves_directory_uid_and_preserves_native_name(self):
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            self.assertEqual(prepare_user('uid'),'opaque@auth.local')
        self.directory.subject.assert_called_once_with('uid')
        self.identity.prepare.assert_called_once_with(uid='uid',login_name='E001',account='E001')
        self.memberships.ensure.assert_not_called()

    def test_disabled_or_changed_uid_cannot_create_native_account(self):
        for value in (subject('disabled'),dict(subject(),userId='other')):
            @contextmanager
            def runtime():
                with self.runtime() as parts:
                    self.directory.subject.return_value=value
                    yield parts
            with patch('cloudfile_ext.v2.etech_directory.runtime',runtime):
                with self.assertRaises(IdentityUnavailable):prepare_user('uid')
            self.identity.prepare.assert_not_called()

    def test_missing_reserved_or_invalid_directory_account_cannot_precreate(self):
        for account in (None, '', 'cfadmin', 'CFADMIN', 'a b', 'a@contact.test'):
            @contextmanager
            def runtime():
                with self.runtime():
                    facts = NativeFacts()
                    native = NativeIdentity(facts, account_schema='accounts', hub_schema='hub',
                                            issuer='https://directory.test', create_account=facts.create)
                    value = subject()
                    value['attributes'] = {'login_name': 'display-only'} if account is None else {'employee_no': account}
                    self.directory.subject.return_value = value
                    yield self.directory, native, self.catalog, self.memberships
            with patch('cloudfile_ext.v2.etech_directory.runtime', runtime), \
                    patch('cloudfile_ext.v2.identity.database_lock', side_effect=lambda *args: nullcontext()), \
                    self.assertRaises((IdentityUnavailable, IdentityConflict)):
                prepare_user('uid')

    def test_prepared_uid_reuses_native_user_with_missing_or_invalid_account_metadata(self):
        for account in (None, '', '中文', 'a@contact.test', ' x ', 'x' * 201):
            facts = NativeFacts()
            facts.profiles.append(('historical@auth.local', 'uid'))
            facts.accounts['historical@auth.local'] = 1
            native = NativeIdentity(facts, account_schema='accounts', hub_schema='hub',
                                    issuer='https://directory.test', create_account=facts.create)
            @contextmanager
            def runtime():
                with self.runtime():
                    value = subject()
                    value['attributes'] = {'employee_no': account}
                    self.directory.subject.return_value = value
                    yield self.directory, native, self.catalog, self.memberships
            with self.subTest(account=account), \
                    patch('cloudfile_ext.v2.etech_directory.runtime', runtime), \
                    patch('cloudfile_ext.v2.identity.database_lock', side_effect=lambda *args: nullcontext()):
                self.assertEqual(prepare_user('uid'), 'historical@auth.local')
                self.assertEqual(facts.created, [])

    def test_group_mapping_uses_exact_type_namespace_and_external_id(self):
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            self.assertEqual(prepare_group('o1'),42)
        self.catalog.ensure.assert_called_once_with('org','directory','o1','Department')
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            with self.assertRaises(IdentityUnavailable):prepare_group('role:o1')
        self.catalog.ensure.assert_not_called()

    def test_default_projector_refreshes_only_current_uid_and_proves_entities(self):
        with patch('cloudfile_ext.v2.etech_directory.runtime',self.runtime):
            ensure_subject('uid','opaque@auth.local')
        self.memberships.ensure.assert_called_once_with('uid','opaque@auth.local')
        self.assertEqual(self.memberships.fetch('uid')['userId'],'uid')
        self.catalog.ensure.assert_called_once_with('org','directory','o1','Department')
        self.directory.entities.side_effect=IdentityUnavailable()
        with self.assertRaises(IdentityUnavailable):self.memberships.fetch('uid')

    def test_connection_requires_scoped_service_credential(self):
        with override_settings(CF_DIRECTORY_URL='https://directory.test/eap/cloudDrive/directory',
                               CF_DIRECTORY_SECRET='',CF_DIRECTORY_KEY_ID='key'):
            with self.assertRaises(IdentityUnavailable):Directory()

    def test_directory_request_is_short_lived_scoped_and_does_not_follow_redirect(self):
        import jwt
        secret='isolated-directory-test-secret-32-bytes'
        response=Mock()
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.status_code=200
        response.iter_content.return_value=[b'{"groups":[]}']
        with override_settings(CF_DIRECTORY_URL='https://directory.test/eap/cloudDrive/directory',
                               CF_DIRECTORY_SECRET=secret,CF_DIRECTORY_KEY_ID='key'), \
                patch('cloudfile_ext.v2.etech_directory.requests.get',return_value=response) as get:
            self.assertEqual(Directory().get('/groups?view=entities'),{'groups':[]})
            kwargs=get.call_args.kwargs
            self.assertFalse(kwargs['allow_redirects'])
            token=kwargs['headers']['Authorization'].split()[1]
            claims=jwt.decode(token,secret,algorithms=['HS256'],audience='eap-directory',issuer='cloudfile-sso')
            self.assertEqual(claims['scope'],'directory.read')
            self.assertEqual(claims['sub'],'cloudfile')
            self.assertEqual(claims['exp']-claims['iat'],60)
            response.status_code=302
            with self.assertRaises(IdentityUnavailable):Directory().get('/groups?view=entities')


    def test_periodic_full_sync_is_delegated_to_v2_owned_catalog(self):
        from cloudfile_ext.v2.etech_directory import sync_entity_catalog
        from cloudfile_ext.v2.full_directory_sync import synchronize
        with patch('cloudfile_ext.v2.etech_directory.runtime', self.runtime), \
             patch('cloudfile_ext.v2.full_directory_sync.synchronize',
                   return_value=dict(status='OK', entities=1,
                                     membership_writes=2, parent_writes=1,
                                     unresolved_count=0)) as reconcile, \
             patch('seahub.utils.db_api.SeafileDB',
                   return_value=SimpleNamespace(db_name='seafile_db')):
            result = sync_entity_catalog()
        self.assertEqual(result['status'], 'OK')
        self.assertEqual(result['membership_writes'], 2)
        reconcile.assert_called_once_with(self.directory, self.catalog,
                self.memberships.redis, 'seafile_db')

    def test_empty_catalog_cannot_report_full_success(self):
        from cloudfile_ext.v2.etech_directory import sync_entity_catalog
        @contextmanager
        def empty_runtime():
            with self.runtime() as parts:
                self.directory.entities.return_value = {}
                yield parts
        with patch('cloudfile_ext.v2.etech_directory.runtime', empty_runtime), \
             patch('seahub.utils.db_api.SeafileDB',
                   return_value=SimpleNamespace(db_name='seafile_db')), \
             self.assertRaises(IdentityUnavailable):
            sync_entity_catalog()
        self.catalog.ensure.assert_not_called()


class SubjectReadyTests(TestCase):
    """Hot path: a committed readiness marker skips the dedicated connection and lock."""
    UID, USER = 'uid', 'opaque@auth.local'

    def setUp(self):
        import json
        from seaserv import ccnet_api
        from seahub.profile.models import Profile
        self.redis = Mock()
        self.redis.eval.return_value = [json.dumps({'uid': self.UID, 'username': self.USER}).encode(), 600000]
        self.binding = [(self.USER, self.UID)]
        self.account = SimpleNamespace(email=self.USER, is_active=True)
        profiles = Mock()
        profiles.filter.return_value.values_list.side_effect = lambda *fields: list(self.binding)
        for target in (patch('cloudfile_ext.v2.etech_directory._shared_redis', return_value=self.redis),
                       patch('cloudfile_ext.v2.etech_directory.redis_location', return_value='redis://cache:6379'),
                       patch('seahub.utils.db_api.SeafileDB', return_value=SimpleNamespace(db_name='seafile_db')),
                       patch.object(Profile, 'objects', profiles),
                       patch.object(ccnet_api, 'get_emailuser', side_effect=lambda user: self.account)):
            target.start()
            self.addCleanup(target.stop)
        self.runtime = Mock(side_effect=AssertionError('locked path must not run'))

    def ensure(self):
        with patch('cloudfile_ext.v2.etech_directory.runtime', self.runtime):
            ensure_subject(self.UID, self.USER)

    def assert_locked_path(self):
        self.runtime.side_effect = None
        @contextmanager
        def runtime():
            parts = tuple(Mock() for _ in range(4))
            yield parts
            parts[3].ensure.assert_called_once_with(self.UID, self.USER)
        self.runtime.side_effect = runtime
        self.ensure()
        self.runtime.assert_called_once()

    def test_ready_subject_skips_dedicated_connection_and_lock(self):
        from cloudfile_ext.v2.memberships import readiness_key
        self.ensure()
        self.runtime.assert_not_called()
        self.assertEqual(self.redis.eval.call_args[0][2], readiness_key('seafile_db', 'etech', self.UID, self.USER))

    def test_fast_and_locked_paths_use_the_same_marker(self):
        from cloudfile_ext.v2.memberships import Memberships, readiness_key
        connection = Mock()
        connection.get_autocommit.return_value = True
        connection.cursor.return_value.__enter__ = Mock(return_value=connection.cursor.return_value)
        connection.cursor.return_value.__exit__ = Mock(return_value=False)
        connection.cursor.return_value.fetchone.return_value = ('seafile_db',)
        memberships = Memberships(connection, Mock(), Mock(), account_schema='ccnet_db', provider='etech', fetch=Mock())
        self.assertEqual(memberships._key(self.UID, self.USER), readiness_key('seafile_db', 'etech', self.UID, self.USER))

    def test_missing_foreign_or_expired_marker_takes_the_locked_path(self):
        import json
        for cached, remaining in ((b'', -2), (json.dumps({'uid': 'other', 'username': self.USER}).encode(), 600000),
                                  (json.dumps({'uid': self.UID, 'username': self.USER}).encode(), -1),
                                  (json.dumps({'uid': self.UID, 'username': self.USER}).encode(), 1800001)):
            with self.subTest(cached=cached, remaining=remaining):
                self.redis.eval.return_value = [cached, remaining]
                self.runtime.reset_mock()
                self.assert_locked_path()

    def test_changed_binding_or_inactive_account_takes_the_locked_path(self):
        self.binding = []
        self.assert_locked_path()
        self.binding, self.account = [(self.USER, self.UID)], SimpleNamespace(email=self.USER, is_active=False)
        self.runtime.reset_mock()
        self.assert_locked_path()
        self.account = None
        self.runtime.reset_mock()
        self.assert_locked_path()

    def test_profile_collation_alias_cannot_become_a_readiness_proof(self):
        # Equality after ORM retrieval must use the exact stored bytes, not
        # the database's potentially case-insensitive field collation.
        self.binding = [(self.USER.upper(), self.UID)]
        self.assert_locked_path()
        self.binding = [(self.USER, self.UID.upper())]
        self.runtime.reset_mock()
        self.assert_locked_path()

    def test_native_account_case_alias_and_nonstandard_status_do_not_bypass_locked_check(self):
        # CE get_emailuser() may match case-insensitively, but the original
        # NativeIdentity.active() compares the actual stored email byte-for-byte.
        self.account = SimpleNamespace(email=self.USER.upper(), is_active=1)
        self.assert_locked_path()
        self.account = SimpleNamespace(email=self.USER, is_active=2)
        self.runtime.reset_mock()
        self.assert_locked_path()

    def test_cache_failure_takes_the_locked_path_which_still_fails_closed(self):
        self.redis.eval.side_effect = ConnectionError('redis down')
        self.assert_locked_path()
        self.runtime.side_effect = IdentityUnavailable('subject projection unavailable')
        with self.assertRaises(IdentityUnavailable):
            self.ensure()

    def test_invalid_subject_ttl_is_not_trusted(self):
        with override_settings(CF_DIRECTORY_SUBJECT_TTL=5):
            self.assert_locked_path()
        self.redis.eval.assert_not_called()
