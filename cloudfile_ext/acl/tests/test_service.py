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


def test_can_manage_library_admin_always(service, monkeypatch):
    monkeypatch.setattr(service, '_is_library_admin', lambda u, r: True)
    monkeypatch.setattr(service, 'is_enabled', lambda name: False)
    assert service.can_manage('u@e.com', 'repo', '/x') is True


def test_can_manage_switch_off_denies_non_admin(service, monkeypatch):
    monkeypatch.setattr(service, '_is_library_admin', lambda u, r: False)
    monkeypatch.setattr(service, 'is_enabled', lambda name: False)
    monkeypatch.setattr(service, '_load_admin_rules', lambda repo_id: [
        {'path': '/a', 'subject_type': 'user', 'subject': 'u@e.com',
         'inherit': 1}])
    assert service.can_manage('u@e.com', 'repo', '/a') is False


def test_can_manage_dir_grant_covers_path(service, monkeypatch):
    monkeypatch.setattr(service, '_is_library_admin', lambda u, r: False)
    monkeypatch.setattr(service, 'is_enabled', lambda name: True)
    monkeypatch.setattr(service, '_load_admin_rules', lambda repo_id: [
        {'path': '/a', 'subject_type': 'user', 'subject': 'u@e.com',
         'inherit': 1}])
    monkeypatch.setattr(service, '_load_subjects',
                        lambda username: resolver.subject_set(username))

    assert service.can_manage('u@e.com', 'repo', '/a/b') is True
    assert service.can_manage('u@e.com', 'repo', '/other') is False


def test_can_manage_loader_failure_fails_closed(service, monkeypatch):
    monkeypatch.setattr(service, '_is_library_admin', lambda u, r: False)
    monkeypatch.setattr(service, 'is_enabled', lambda name: True)

    def boom(repo_id):
        raise RuntimeError('db down')

    monkeypatch.setattr(service, '_load_admin_rules', boom)
    assert service.can_manage('u@e.com', 'repo', '/x') is False

# Exercise request reuse, shared TTL and write/read races on the actual loaders.
# An empty policy is data, not a miss; invalidation must defeat an old refill.
class MemoryCache:
    def __init__(self):
        self.values, self.reads, self.writes = {}, [], []

    def get(self, key, default=None):
        self.reads.append(key)
        return self.values.get(key, default)

    def set(self, key, value, timeout):
        self.values[key] = value
        self.writes.append((key, timeout))

    def delete(self, key):
        self.values.pop(key, None)


def test_directory_reuses_empty_policy_once_and_discards_request_inputs(service, monkeypatch):
    from unittest.mock import Mock
    cache = MemoryCache()
    manager = types.SimpleNamespace(rules_for_repo=Mock(return_value=[]))
    monkeypatch.setattr(service, 'cache', cache)
    monkeypatch.setitem(sys.modules, 'cloudfile_ext.acl.models', types.SimpleNamespace(
        DirACL=types.SimpleNamespace(objects=manager)))
    with service.directory_inputs():
        for _ in range(200):
            assert service._load_rules('repo') == []
    assert len(cache.reads) == 2  # namespace and value, not 200 Redis reads
    assert cache.writes == [('cf_acl_rules_repo:0', 60)]
    service._load_rules('repo')
    assert len(cache.reads) == 4
    manager.rules_for_repo.assert_called_once_with('repo')


def test_rule_write_cannot_be_undone_by_an_inflight_old_refill(service, monkeypatch):
    from unittest.mock import Mock
    cache = MemoryCache()
    def old_read(repo):
        service.invalidate_repo(repo)
        return ['old']
    manager = types.SimpleNamespace(rules_for_repo=Mock(side_effect=old_read))
    monkeypatch.setattr(service, 'cache', cache)
    monkeypatch.setitem(sys.modules, 'cloudfile_ext.acl.models', types.SimpleNamespace(
        DirACL=types.SimpleNamespace(objects=manager)))
    assert service._load_rules('repo') == ['old']
    manager.rules_for_repo.side_effect = lambda repo: ['new']
    assert service._load_rules('repo') == ['new']
    assert manager.rules_for_repo.call_count == 2
