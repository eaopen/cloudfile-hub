"""V2 login-first and staff-first creation execute without the legacy framework."""
from contextlib import nullcontext
from datetime import datetime, timezone
import unittest
from unittest.mock import Mock, patch

from cloudfile_ext.v2.errors import IdentityConflict, IdentityUnavailable
from cloudfile_ext.v2.identity import NativeIdentity
from cloudfile_ext.v2.jit import SQLJITProvisioner
from cloudfile_ext.v2.tests.native_identity_facts import NativeFacts


class OIDCProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.facts = NativeFacts()
        self.native = NativeIdentity(self.facts, account_schema='accounts', hub_schema='hub',
                                     issuer='https://directory.test', create_account=self.facts.create)
        self.account, self.status, self.uid = '10280993', 'active', None
        self.directory = Mock()
        self.directory.subject.side_effect = self.source
        self.jit = SQLJITProvisioner(self.directory, self.native)
        for target in ('cloudfile_ext.v2.jit.database_lock', 'cloudfile_ext.v2.identity.database_lock'):
            mocked = patch(target, side_effect=lambda *args, **kwargs: nullcontext())
            mocked.start()
            self.addCleanup(mocked.stop)

    def source(self, uid):
        return dict(userId=self.uid or uid, status=self.status,
                    attributes={'employee_no': self.account, 'email': 'shared@contact.test'},
                    organizations=[], organization_ancestors=[], roles=[], etag='revision',
                    generated_at=datetime.now(timezone.utc).isoformat())

    def login(self, uid='uid', provider='idp-one', subject='sub-one'):
        return self.jit.ensure(uid=uid, provider=provider, subject=subject)

    def test_login_first_then_staff_and_repeat_login_keep_one_native_user(self):
        self.assertEqual(self.login(), '10280993@auth.local')
        self.assertEqual(self.native.prepare(uid='uid', login_name='renamed', account='renamed'), '10280993@auth.local')
        self.assertEqual(self.login(), '10280993@auth.local')
        self.assertEqual(self.facts.created, ['10280993@auth.local'])
        self.assertEqual(len(self.facts.social), 1)

    def test_staff_first_and_second_provider_bind_to_the_same_uid(self):
        self.native.prepare(uid='uid', login_name=self.account, account=self.account)
        self.assertEqual(self.login(), '10280993@auth.local')
        self.account = 'renamed'
        self.assertEqual(self.login(provider='idp-two', subject='another-sub'), '10280993@auth.local')
        self.assertEqual(self.facts.created, ['10280993@auth.local'])
        self.assertEqual(len(self.facts.social), 2)

    def test_shared_contact_email_and_nonnumeric_accounts_never_merge(self):
        for uid, account in (('one', '10280993'), ('two', 'zhangsan'), ('three', 'admin'), ('four', 'EMP-A')):
            self.account = account
            self.assertEqual(self.login(uid=uid, subject=uid), account.lower() + '@auth.local')
        self.assertEqual(len(self.facts.accounts), 4)
        self.assertEqual(len(self.facts.profiles), 4)
        self.account = 'emp-a'
        with self.assertRaises(IdentityConflict): self.login(uid='case-collision', subject='case-collision')
        self.assertEqual(len(self.facts.accounts), 4)

    def test_missing_invalid_reserved_or_disabled_directory_identity_cannot_create(self):
        for account in (None, '', 'cfadmin', 'CFADMIN', 'a b', 'a@contact.test'):
            self.account = account
            with self.assertRaises((IdentityConflict, IdentityUnavailable)): self.login()
        self.account, self.status = 'admin', 'disabled'
        with self.assertRaises(IdentityUnavailable): self.login()
        self.status, self.uid = 'active', 'different-uid'
        with self.assertRaises(IdentityUnavailable): self.login()
        self.assertEqual(self.facts.created, [])

    def test_existing_historical_native_account_is_preserved(self):
        self.facts.profiles.append(('historical-uuid@auth.local', 'uid'))
        self.facts.accounts['historical-uuid@auth.local'] = 1
        self.assertEqual(self.login(), 'historical-uuid@auth.local')
        self.assertEqual(self.facts.created, [])

    def test_provider_subject_conflict_is_rejected_before_any_new_account(self):
        self.login()
        self.account = 'zhangsan'
        with self.assertRaises(IdentityConflict): self.login(uid='other-uid')
        self.assertEqual(self.facts.created, ['10280993@auth.local'])
        self.assertEqual(len(self.facts.social), 1)

    def test_rpc_failure_never_publishes_profile_or_authentication_binding(self):
        self.native.create_account = Mock(side_effect=IdentityUnavailable('RPC unavailable'))
        with self.assertRaises(IdentityUnavailable): self.login()
        self.assertEqual(self.facts.profiles, [])
        self.assertEqual(self.facts.social, [])

    def test_failed_binding_is_retried_on_the_same_precreated_native_user(self):
        execute = self.facts.execute
        def fail_binding(sql, args=()):
            if sql.startswith('INSERT INTO') and 'social_auth_usersocialauth' in sql:
                raise RuntimeError('binding unavailable')
            return execute(sql, args)
        with patch.object(self.facts, 'execute', side_effect=fail_binding):
            with self.assertRaises(RuntimeError): self.login()
        self.assertEqual(self.facts.social, [])
        self.assertEqual(self.login(), '10280993@auth.local')
        self.assertEqual(self.facts.created, ['10280993@auth.local'])

    def test_name_uid_case_and_inactive_conflicts_do_not_create_or_bind(self):
        for profiles, accounts in (
                ([('old@auth.local', 'uid')], {'old@auth.local': 0}),
                ([('old@auth.local', 'UID')], {'old@auth.local': 1}),
                ([('a@auth.local', 'uid'), ('b@auth.local', 'uid')], {'a@auth.local': 1, 'b@auth.local': 1}),
                ([('10280993@auth.local', 'another-uid')], {'10280993@auth.local': 1}),
                ([], {'10280993@AUTH.local': 1})):
            self.facts.accounts, self.facts.profiles = accounts, profiles
            with self.assertRaises((IdentityConflict, IdentityUnavailable)): self.login()
        self.assertEqual(self.facts.created, [])
        self.assertEqual(self.facts.social, [])
