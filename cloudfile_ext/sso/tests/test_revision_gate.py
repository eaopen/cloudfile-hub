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
