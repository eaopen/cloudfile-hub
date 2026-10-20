"""Account/UID state transitions with SQL-boundary doubles; no database I/O.

These tests execute both provisioning implementations and native binding
selection. They do not claim RPC, collation or transactional integration proof.
"""
from contextlib import nullcontext
from copy import deepcopy
import unittest
from unittest.mock import Mock, patch

from cloudfile_ext.v2.account_names import account_username
from cloudfile_ext.v2.identity import NativeIdentity
from cloudfile_ext.v2.errors import IdentityConflict, IdentityUnavailable
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.provider import DirectoryProvider
from cloudfile_extensions.identity.jit import SQLJITProvisioner
from cloudfile_extensions.identity.sql_bindings import SQLIdentityBindings


class NativeFacts:
    """Model CE's case-insensitive lookup while returning exact stored values."""
    def __init__(self):
        self.accounts, self.profiles, self.social = {}, [], []
        self.rows, self.snapshot = (), None
        self.created = []

    def get_autocommit(self): return True
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def fetchall(self): return tuple(self.rows)
    def begin(self): self.snapshot = deepcopy((self.accounts, self.profiles, self.social))
    def commit(self): self.snapshot = None
    def rollback(self):
        if self.snapshot is not None:
            self.accounts, self.profiles, self.social = self.snapshot
            self.snapshot = None

    def create(self, username):
        if any(name.lower() == username.lower() for name in self.accounts):
            raise AssertionError('RPC must never adopt an existing account')
        self.created.append(username)
        self.accounts[username] = 1

    def execute(self, sql, args=()):
        self.rows = ()
        sql = sql.replace("`", "")
        if sql.startswith('SELECT'):
            if '.profile_profile' in sql:
                if 'WHERE user=%s OR login_id=%s' in sql:
                    rows = [r for r in self.profiles if r[0].lower() == args[0].lower() or r[1].lower() == args[1].lower()]
                elif 'WHERE login_id=%s' in sql:
                    rows = [r for r in self.profiles if r[1].lower() == args[0].lower()]
                else:
                    rows = [r for r in self.profiles if r[0].lower() == args[0].lower()]
                self.rows = rows
            elif '.EmailUser' in sql:
                rows = [(name, active) for name, active in self.accounts.items() if name.lower() == args[0].lower()]
                self.rows = rows if 'email,is_active' in sql else [(r[0],) for r in rows]
            elif '.social_auth_usersocialauth' in sql:
                self.rows = [r for r in self.social if r[1:3] == args]
            else:
                raise AssertionError(sql)
        elif sql.startswith('INSERT INTO'):
            if '.EmailUser' in sql:
                self.create(args[0])
            elif '.profile_profile' in sql:
                self.profiles.append(tuple(args[:2]))
            elif '.social_auth_usersocialauth' in sql:
                self.social.append(tuple(args))
            else:
                raise AssertionError(sql)
        else:
            raise AssertionError(sql)


class AccountProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.facts = NativeFacts()
        self.native = NativeIdentity(self.facts, account_schema='accounts', hub_schema='hub',
                                     issuer='https://directory.test', create_account=self.facts.create)
        for target in ('cloudfile_ext.v2.identity.database_lock',
                       'cloudfile_extensions.identity.jit.database_lock',
                       'cloudfile_extensions.identity.jit.scope_locks',
                       'cloudfile_extensions.identity.sql_bindings.scope_locks'):
            mocked = patch(target, side_effect=lambda *args, **kwargs: nullcontext())
            mocked.start()
            self.addCleanup(mocked.stop)
        for target in ('cloudfile_extensions.identity.jit.SchemaRunner.require_current',
                       'cloudfile_extensions.identity.sql_bindings.SQLIdentityBindings._engines',
                       'cloudfile_extensions.identity.jit.EventWriter.append'):
            mocked = patch(target)
            mocked.start()
            self.addCleanup(mocked.stop)

    def jit(self, account='10280993', *, provider='etech', issuer='https://idp.test', status='active'):
        directory = Mock(spec=DirectoryProvider)
        attributes = {} if account is None else {'employee_no': account}
        directory.fetch.return_value = dict(userId='uid', status=status, attributes=attributes)
        bindings = SQLIdentityBindings(self.facts, native_schema='accounts', identity_schema='hub',
                                       directory_provider=provider, authorize=Mock(), audit=Mock())
        jit = SQLJITProvisioner(bindings, issuer=issuer, directory=directory, enabled=True, request_id='test')
        jit.state = Mock()
        jit.state.barrier_active.return_value = False
        return jit, dict(issuer=issuer, sub='sub', userId='uid')

    def test_both_entry_orders_converge_without_renaming_or_extra_users(self):
        for first in ('prepare', 'login'):
            with self.subTest(first=first):
                self.facts.accounts.clear(); self.facts.profiles.clear(); self.facts.social.clear(); self.facts.created.clear()
                jit, claims = self.jit()
                if first == 'prepare':
                    self.assertEqual(self.native.prepare(uid='uid', login_name='10280993', account='10280993'), '10280993@auth.local')
                username = jit.ensure(claims)
                self.assertEqual(self.native.prepare(uid='uid', login_name='changed', account='changed'), username)
                self.assertEqual(jit.ensure(claims), username)
                self.assertEqual(self.facts.created, ['10280993@auth.local'])

    def test_nonnumeric_accounts_and_admin_are_normal_nonstaff_names(self):
        for account in ('10280993', 'zhangsan', 'admin', 'EMP-A', '001'):
            with self.subTest(account=account):
                self.facts.accounts.clear(); self.facts.profiles.clear(); self.facts.social.clear()
                jit, claims = self.jit(account)
                self.assertEqual(jit.ensure(claims), account_username(account))

    def test_missing_invalid_or_reserved_new_etech_account_never_falls_back(self):
        for account in (None, '', 'cfadmin', 'CFADMIN', ' a', 'a b', 'a@x', '张三', 'a'*201):
            with self.subTest(account=account), self.assertRaises(ContractError):
                jit, claims = self.jit(account)
                jit.ensure(claims)
        self.assertEqual(self.facts.created, [])

    def test_existing_historical_uid_owner_accepts_another_idp_only(self):
        self.facts.accounts['historical-uuid@auth.local'] = 1
        self.facts.profiles.append(('historical-uuid@auth.local', 'uid'))
        for issuer in ('https://idp-one.test', 'https://idp-two.test'):
            jit, claims = self.jit(None, issuer=issuer)
            self.assertEqual(jit.ensure(claims), 'historical-uuid@auth.local')
        self.assertEqual(self.native.prepare(uid='uid', login_name='new', account='new'), 'historical-uuid@auth.local')
        self.assertEqual(len(self.facts.social), 2)
        self.assertEqual(self.facts.created, [])

    def test_second_provider_links_even_when_new_account_jit_is_disabled(self):
        self.facts.accounts['historical@auth.local'] = 1
        self.facts.profiles.append(('historical@auth.local', 'uid'))
        jit, claims = self.jit(issuer='https://second.test')
        jit.enabled = False
        jit.state.username.return_value = 'historical@auth.local'
        self.assertEqual(jit.link_existing(claims), 'historical@auth.local')
        self.assertEqual(len(self.facts.social), 1)
        self.assertEqual(self.facts.created, [])

    def test_collisions_and_inactive_or_ambiguous_uid_cannot_merge(self):
        for profiles, accounts in (
                ([('other@auth.local', 'UID')], {'other@auth.local': 1}),
                ([('old@auth.local', 'uid')], {'old@auth.local': 0}),
                ([('a@auth.local', 'uid'), ('b@auth.local', 'uid')], {'a@auth.local': 1, 'b@auth.local': 1}),
                ([('10280993@auth.local', 'other-uid')], {'10280993@auth.local': 1}),
                ([], {'10280993@AUTH.local': 1})):
            with self.subTest(profiles=profiles, accounts=accounts):
                self.facts.profiles, self.facts.accounts = profiles, accounts
                jit, claims = self.jit()
                with self.assertRaises(ContractError): jit.ensure(claims)
                with self.assertRaises((IdentityConflict, IdentityUnavailable)):
                    self.native.prepare(uid='uid', login_name='10280993', account='10280993')
        self.assertEqual(self.facts.created, [])

    def test_generic_directory_keeps_opaque_naming_and_disabled_directory_denies(self):
        jit, claims = self.jit(None, provider='generic')
        self.assertRegex(jit.ensure(claims), r'^[0-9a-f]{32}@auth.local$')
        self.facts.accounts.clear(); self.facts.profiles.clear(); self.facts.social.clear()
        jit, claims = self.jit(status='disabled')
        with self.assertRaises(ContractError): jit.ensure(claims)


class LegacyProvisioningDelegationTests(unittest.TestCase):
    def test_legacy_creation_uses_v2_uid_authority(self):
        from types import SimpleNamespace
        from django.test import override_settings
        from cloudfile_ext.identity_api import AdminExternalIdentityView
        from cloudfile_ext.v2.http import IdentityResolve
        with override_settings(CF_DIRECTORY_URL='https://directory.test'), \
                patch.object(IdentityResolve, 'post', return_value='delegated') as resolve:
            request = SimpleNamespace(data={'external_user_id': 'uid', 'login_id': 'uid'})
            self.assertEqual(AdminExternalIdentityView().post(request), 'delegated')
            resolve.assert_called_once_with(request)

