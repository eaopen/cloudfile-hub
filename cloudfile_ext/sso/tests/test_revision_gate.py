# -*- coding: utf-8 -*-
"""The policy_revision gate on desired-state PUTs (decision 2026-08-28 §8.2).

The damage path: a delayed retry replays an old desired state over a newer
policy and silently re-shares a library that has since been tightened. The
gate refuses anything older than the highest accepted revision, in one
whole-request refusal rather than a partial apply.

Django-free like the rest of cloudfile_ext's tests: the ORM seam is
monkeypatched, following test_service.py's stub pattern.
"""

import importlib
import sys
import types

import pytest

from cloudfile_ext.sso import library_share_policy


def _stub_django(monkeypatch):
    models = types.ModuleType('django.db.models')

    def _field(*args, **kwargs):
        return None

    class FakeObjects(object):
        def as_dict(self, provider):
            return {}

    class FakeModel(object):
        objects = FakeObjects()

    models.Model = FakeModel
    models.Manager = object
    for name in ('CharField', 'IntegerField', 'BigIntegerField', 'TextField'):
        setattr(models, name, _field)

    db = types.ModuleType('django.db')
    db.models = models
    django = types.ModuleType('django')
    django.db = db
    for name, mod in (('django', django), ('django.db', db),
                      ('django.db.models', models)):
        monkeypatch.setitem(sys.modules, name, mod)


@pytest.fixture
def svc(monkeypatch):
    _stub_django(monkeypatch)
    for name in ('cloudfile_ext.sso.library_share_service',
                 'cloudfile_ext.sso.library_shares'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    module = importlib.import_module('cloudfile_ext.sso.library_share_service')

    from contextlib import nullcontext
    monkeypatch.setattr(module, '_revision_lock', lambda _: nullcontext())
    state = {'rev': None}
    monkeypatch.setattr(module, '_read_accepted_revision',
                        lambda repo_id: state['rev'])
    monkeypatch.setattr(module, '_record_revision',
                        lambda repo_id, rev: state.__setitem__('rev', rev))
    module._test_state = state
    return module


def test_first_revision_establishes_the_contract(svc, monkeypatch):
    # apply() reaches the DB/seaserv layers below the gate; the gate itself is
    # what this test watches, so stub the whole apply pipeline after it.
    calls = {}

    def fake_plan_for(repo_id, desired):
        calls['planned'] = True
        return library_share_policy.SharePlan(add=[], update=[],
                                              revoke=[], errors=[])

    def fake_owner(repo_id):
        return 'owner@example.com'

    monkeypatch.setattr(svc, 'plan_for', fake_plan_for)
    monkeypatch.setattr(svc, '_repo_owner', fake_owner)
    monkeypatch.setattr(svc, '_seafile_api', lambda: object())
    report = svc.apply('repo', [library_share_policy.DesiredShare('g1', 'r')],
                       policy_revision=7)
    assert calls.get('planned')
    assert report['revision'] == 7
    assert svc._test_state['rev'] == 7


def test_equal_and_newer_pass(svc):
    svc._test_state['rev'] = 42
    svc.check_revision('repo', 42)
    svc.check_revision('repo', 43)


def test_stale_is_refused_whole(svc):
    svc._test_state['rev'] = 42
    with pytest.raises(svc.StaleRevision) as exc:
        svc.check_revision('repo', 41)
    assert exc.value.accepted == 42
    assert exc.value.rejected == 41


def test_none_revision_keeps_legacy_contract(svc):
    svc._test_state['rev'] = 42
    svc.check_revision('repo', None)


def test_native_drift_is_repaired_even_when_ledger_matches(svc, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    api = Mock()
    native = {'permission': 'r'}
    api.get_group_shared_repo_by_path.side_effect = lambda *args: SimpleNamespace(permission=native['permission'])
    api.set_group_repo_permission.side_effect = lambda gid, repo, perm: native.update(permission=perm)
    ledger = {'dept': {'seafile_group_id': 7, 'permission': 'rw', 'state': 'ACTIVE'}}
    monkeypatch.setattr(svc.ManagedLibraryShare, 'objects', Mock())
    svc.ManagedLibraryShare.objects.as_dict.return_value = ledger
    monkeypatch.setattr(svc, '_resolved_groups', lambda: {'dept': 7})
    monkeypatch.setattr(svc, '_seafile_api', lambda: api)
    monkeypatch.setattr(svc, '_repo_owner', lambda _: 'owner')
    report = svc.apply('repo', [library_share_policy.DesiredShare('dept', 'rw')], 1)
    assert report['applied']['update'] == 1 and report['errors'] == []
    assert native['permission'] == 'rw'
    svc.ManagedLibraryShare.objects.record_applied.assert_called_once()


def test_failed_native_readback_never_records_success(svc, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    api = Mock()
    api.get_group_shared_repo_by_path.return_value = SimpleNamespace(permission='r')
    monkeypatch.setattr(svc.ManagedLibraryShare, 'objects', Mock())
    svc.ManagedLibraryShare.objects.as_dict.return_value = {}
    monkeypatch.setattr(svc, '_resolved_groups', lambda: {'dept': 7})
    monkeypatch.setattr(svc, '_seafile_api', lambda: api)
    monkeypatch.setattr(svc, '_repo_owner', lambda _: 'owner')
    report = svc.apply('repo', [library_share_policy.DesiredShare('dept', 'rw')], 1)
    assert report['errors'] and report['applied']['add'] == 0
    svc.ManagedLibraryShare.objects.record_applied.assert_not_called()
    svc.ManagedLibraryShare.objects.record_error.assert_called_once()


@pytest.mark.parametrize('notes', [
    {'revision': 'same', 'unresolved': ['missing'], 'quarantined_groups': []},
    {'revision': 'same', 'unresolved': [], 'quarantined_groups': ['dept']},
])
def test_incomplete_directory_reports_partial_and_remains_retryable(svc, monkeypatch, notes):
    from types import SimpleNamespace
    from cloudfile_ext.sso import service
    monkeypatch.setitem(sys.modules, 'cloudfile_ext.registry', SimpleNamespace(registry=object()))
    monkeypatch.setattr(service.directory, 'active', lambda _: object())
    monkeypatch.setattr(service, 'group_owner', lambda: 'owner')
    plan = SimpleNamespace(empty=True, counts=lambda: {})
    monkeypatch.setattr(service, 'build_plan', lambda _: (plan, notes))
    monkeypatch.setattr(service, '_apply', lambda *args: ({}, []))
    monkeypatch.setattr(service, '_record', lambda status, detail: {'status': status, 'detail': detail})
    result = service.sync()
    assert result['status'] == service.STATUS_PARTIAL


def test_revision_check_and_native_writes_share_the_same_lock(svc, monkeypatch):
    from contextlib import contextmanager
    active = {'locked': False}
    @contextmanager
    def lock(repo):
        active['locked'] = True
        try: yield
        finally: active['locked'] = False
    def read(repo):
        assert active['locked']
        return 9
    monkeypatch.setattr(svc, '_revision_lock', lock)
    monkeypatch.setattr(svc, '_read_accepted_revision', read)
    with pytest.raises(svc.StaleRevision):
        svc.apply('repo', [], policy_revision=8)
    assert not active['locked']


def test_directory_sync_preserves_technical_owner_in_legacy_groups(svc, monkeypatch):
    from types import SimpleNamespace
    from cloudfile_ext.sso import service
    api = SimpleNamespace(
        get_group=lambda gid: SimpleNamespace(creator_name='legacy-owner'),
        get_group_members=lambda gid: [SimpleNamespace(user_name=name)
                                      for name in ('technical-owner', 'employee')])
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(ccnet_api=api))
    monkeypatch.setattr(service, 'group_owner', lambda: 'technical-owner')
    members, protected, stale = service._current_state({'dept': {'group_id': 7}})
    assert members[7] == ['technical-owner', 'employee']
    assert set(protected[7]) == {'legacy-owner', 'technical-owner'}
    assert stale == []


def test_sync_report_bounds_repeated_identity_failures(svc):
    import json
    from cloudfile_ext.sso import service
    detail = {'unresolved': ['missing'] * 50000,
              'quarantined_groups': ['dept'], 'revision': 'current'}
    report = json.loads(service._describe(detail))
    assert report['unresolved_count'] == 50000
    assert report['unresolved_unique_count'] == 1
    assert report['unresolved'] == ['missing']
    assert len(detail['unresolved']) == 50000
    assert report['revision'] == 'current'


@pytest.mark.parametrize('errors', [[], ['add broken-member failed']])
def test_partial_sync_keeps_healthy_changes_and_retries_missing_members(svc, monkeypatch, errors):
    import json
    from types import SimpleNamespace
    from unittest.mock import Mock
    from cloudfile_ext.sso import service
    monkeypatch.setitem(sys.modules, 'cloudfile_ext.registry', SimpleNamespace(registry=object()))
    monkeypatch.setattr(service.directory, 'active', lambda _: object())
    monkeypatch.setattr(service, 'group_owner', lambda: 'owner')
    plan = SimpleNamespace(empty=False, counts=lambda: {'add': 2})
    notes = {'revision': 'same', 'unresolved': ['missing'], 'quarantined_groups': ['dept']}
    monkeypatch.setattr(service, 'build_plan', lambda _: (plan, notes))
    apply = Mock(return_value=({'add': 1}, errors))
    monkeypatch.setattr(service, '_apply', apply)
    monkeypatch.setattr(service, '_record', lambda status, detail: {'status': status, 'detail': detail})
    for _ in range(2):
        result = service.sync()
        assert result['status'] == service.STATUS_PARTIAL
        assert json.loads(result['detail'])['applied']['add'] == 1
    assert apply.call_count == 2
    notes['unresolved'] = []
    notes['quarantined_groups'] = []
    apply.return_value = ({'add': 2}, [])
    assert service.sync()['status'] == service.STATUS_OK


def test_directory_transport_failure_is_still_a_whole_sync_error(svc, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from cloudfile_ext.sso import service
    monkeypatch.setitem(sys.modules, 'cloudfile_ext.registry', SimpleNamespace(registry=object()))
    monkeypatch.setattr(service.directory, 'active', lambda _: object())
    monkeypatch.setattr(service, 'group_owner', Mock(side_effect=service.SyncNotConfigured('unavailable')))
    apply = Mock()
    monkeypatch.setattr(service, '_apply', apply)
    monkeypatch.setattr(service, '_record', lambda status, detail: {'status': status, 'detail': detail})
    assert service.sync()['status'] == service.STATUS_ERROR
    apply.assert_not_called()
