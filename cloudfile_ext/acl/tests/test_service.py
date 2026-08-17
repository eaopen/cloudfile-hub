# -*- coding: utf-8 -*-
"""acl.service.is_path_denied's visibility contract, without Django.

service.py imports django.conf/django.core.cache at module scope, so this
stubs those the same way test_providers.py stubs django.conf, then
monkeypatches the two loaders and the feature switch to exercise the decision
and its fail-closed path directly.
"""

import importlib
import sys
import types

import pytest

from cloudfile_ext.acl import resolver


def _stub_django(monkeypatch):
    conf = types.ModuleType('django.conf')
    conf.settings = types.SimpleNamespace()
    cache_mod = types.ModuleType('django.core.cache')
    cache_mod.cache = object()
    core = types.ModuleType('django.core')
    core.cache = cache_mod
    django = types.ModuleType('django')
    django.conf = conf
    django.core = core
    for name, mod in (('django', django), ('django.conf', conf),
                      ('django.core', core),
                      ('django.core.cache', cache_mod)):
        monkeypatch.setitem(sys.modules, name, mod)


@pytest.fixture
def service(monkeypatch):
    _stub_django(monkeypatch)
    # features.py reads django.conf.settings, and service.py imports both, so
    # drop any earlier imports to re-execute them against the stub.
    for name in ('cloudfile_ext.features', 'cloudfile_ext.acl.service'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    return importlib.import_module('cloudfile_ext.acl.service')


def test_switch_off_never_denies(service, monkeypatch):
    monkeypatch.setattr(service, 'is_enabled', lambda name: False)
    assert service.is_path_denied('u@e.com', 'repo', '/x') is False


def test_denying_rule_hides_path_and_grant_keeps_it(service, monkeypatch):
    monkeypatch.setattr(service, 'is_enabled', lambda name: True)
    monkeypatch.setattr(service, '_load_rules', lambda repo_id: [
        {'path': '/hr', 'subject_type': 'user', 'subject': 'u@e.com',
         'permission': 'invisible', 'inherit': 1},
    ])
    monkeypatch.setattr(service, '_load_subjects',
                        lambda username: resolver.subject_set(username))

    assert service.is_path_denied('u@e.com', 'repo', '/hr/a.txt') is True
    assert service.is_path_denied('u@e.com', 'repo', '/public/a.txt') is False


def test_no_rules_keeps_path_visible(service, monkeypatch):
    monkeypatch.setattr(service, 'is_enabled', lambda name: True)
    monkeypatch.setattr(service, '_load_rules', lambda repo_id: [])
    assert service.is_path_denied('u@e.com', 'repo', '/x') is False


def test_loader_failure_fails_closed(service, monkeypatch):
    monkeypatch.setattr(service, 'is_enabled', lambda name: True)

    def boom(repo_id):
        raise RuntimeError('db down')

    monkeypatch.setattr(service, '_load_rules', boom)
    assert service.is_path_denied('u@e.com', 'repo', '/x') is True


def test_subject_failure_fails_closed(service, monkeypatch):
    monkeypatch.setattr(service, 'is_enabled', lambda name: True)
    monkeypatch.setattr(service, '_load_rules', lambda repo_id: [
        {'path': '/hr', 'subject_type': 'user', 'subject': 'u@e.com',
         'permission': 'invisible', 'inherit': 1},
    ])

    def boom(username):
        raise RuntimeError('ccnet down')

    monkeypatch.setattr(service, '_load_subjects', boom)
    assert service.is_path_denied('u@e.com', 'repo', '/hr/a.txt') is True
