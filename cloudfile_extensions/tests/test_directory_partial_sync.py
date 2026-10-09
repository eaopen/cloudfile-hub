"""Partial member failures must not invalidate healthy directory changes."""
import importlib
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, MagicMock

import pytest


@pytest.fixture
def runtime(monkeypatch):
    config = dict(provider='etech', directory_url='https://directory.example/api',
                  identity_schema='identity', native_schema='native')
    settings = SimpleNamespace(CLOUDFILE_POLICY_CONFIG=config, CF_SSO_GROUP_OWNER='technical')
    api = Mock()
    def stub(name, **values):
        module = ModuleType(name)
        module.__dict__.update(values)
        monkeypatch.setitem(sys.modules, name, module)
    stub('django.conf', settings=settings)
    stub('seaserv', ccnet_api=api, seafile_api=Mock())
    stub('seahub.base.accounts', User=SimpleNamespace(objects=SimpleNamespace(
        get=lambda **kw: SimpleNamespace(is_active=True, username='technical'))))
    stub('cloudfile_extensions.authorization.service_configuration',
         directory_authorization=lambda *args: lambda: 'private-in-memory')
    client = Mock()
    client.get.return_value = {'revision': 'same', 'groups': [
        {'external_id': '27', 'name': 'Dept', 'subject_type': 'dept',
         'member_user_ids': ['healthy', 'missing']}]}
    stub('cloudfile_extensions.common.http', HttpsJsonClient=lambda **kw: client,
         trusted_https_url=lambda url: url)
    stub('cloudfile_extensions.common.validation', identifier=lambda value, **kw: value)
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = (1,)
    stub('cloudfile_extensions.library_shares', _database=lambda: connection)
    stub('cloudfile_extensions.directory.project', qualified=lambda schema, table: table)
    monkeypatch.delitem(sys.modules, 'cloudfile_extensions.directory.sync', raising=False)
    module = importlib.import_module('cloudfile_extensions.directory.sync')
    monkeypatch.setattr(module, '_read_mapped', lambda *args: {})
    bound_users = module._bound_users
    monkeypatch.setattr(module, '_bound_users', lambda *args: {'healthy': 'native-healthy'})
    return SimpleNamespace(module=module, api=api, cursor=cursor, client=client, bound_users=bound_users)


@pytest.mark.parametrize('errors', [[], ['add broken-member']])
def test_partial_run_preserves_applied_changes_and_reports_pending_work(runtime, monkeypatch, errors):
    apply = Mock(return_value=({'add': 1}, errors))
    monkeypatch.setattr(runtime.module, '_apply', apply)
    for _ in range(2):
        result = runtime.module.sync()
        assert result['status'] == 'PARTIAL'
        assert result['applied']['add'] == 1
        assert result['unresolved_user_ids'] == ['missing']
        assert result['quarantined_group_count'] == 1
        assert result['error_count'] == len(errors)
    assert apply.call_count == 2
    assert apply.call_args.args[0].create[0]['members'] == ['native-healthy']


def test_new_group_continues_after_one_member_write_fails(runtime):
    runtime.api.create_group.return_value = 42
    runtime.api.group_add_member.side_effect = [RuntimeError('broken member'), None]
    plan = runtime.module.reconcile.Plan()
    plan.create = [dict(external_id='27', name='Dept', subject_type='dept',
                        parent_external_id=None, members=['broken', 'healthy'])]
    done, errors = runtime.module._apply(plan, runtime.cursor, 'etech', 'technical', {})
    assert done['create'] == 1 and done['add'] == 1
    assert len(errors) == 1 and errors[0].startswith('add broken')
    assert runtime.api.group_add_member.call_args.args == (42, 'technical', 'healthy')


def test_technical_owner_is_protected_with_different_legacy_creator(runtime):
    runtime.api.get_group.return_value = SimpleNamespace(creator_name='legacy')
    runtime.api.get_group_members.return_value = [SimpleNamespace(user_name='technical')]
    runtime.cursor.fetchall.return_value = ((-1,),)
    mapped = {'27': dict(group_id=42, parent_external_id=None)}
    entries = [dict(external_id='27', parent_external_id=None, subject_type='dept')]
    members, protected = runtime.module._native_state(mapped, entries, runtime.cursor,
                                                      'native', 'technical')
    assert members[42] == ['technical']
    assert set(protected[42]) == {'legacy', 'technical'}


def test_directory_unavailable_still_prevents_application(runtime, monkeypatch):
    runtime.client.get.side_effect = RuntimeError('unavailable')
    apply = Mock()
    monkeypatch.setattr(runtime.module, '_apply', apply)
    with pytest.raises(RuntimeError):
        runtime.module.sync()
    apply.assert_not_called()


@pytest.mark.parametrize('rows', [
    [('native-a', 'broken'), ('native-b', 'broken'), ('native-good', 'healthy')],
    [('native-shared', 'broken'), ('native-shared', 'also-broken'), ('native-good', 'healthy')],
])
def test_conflicting_bindings_do_not_block_healthy_employees(runtime, rows):
    runtime.cursor.fetchall.return_value = rows
    result = runtime.bound_users(runtime.cursor, ['broken', 'also-broken', 'healthy'], 'identity')
    assert result == {'healthy': 'native-good'}
