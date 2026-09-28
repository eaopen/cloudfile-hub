# -*- coding: utf-8 -*-
"""PermissionService facade contract (permission-tables.md 4.4).

The facade must forward exactly to the canonical decisions in
cloudfile_ext.acl.service -- that is what keeps check_folder_permission and
its 351 call sites on the same code path. The forwards tests freeze that
delegation: if someone replaces it with a re-implementation (e.g. feeding the
repo-level check_permission result instead of the path-aware native), these
tests fail before any caller notices.
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
def svc(monkeypatch):
    """acl.service reloaded against stub django, with permissions imported."""
    _stub_django(monkeypatch)
    # delitem on sys.modules does not clear the package attribute: after the
    # first reload, `from cloudfile_ext.acl import service` inside permissions
    # would bind the *stale* module from a previous test. Drop the attribute
    # too so every reload rebinds to the fresh module.
    import cloudfile_ext.acl as acl_pkg
    monkeypatch.delattr(acl_pkg, 'service', raising=False)
    # features.py reads django.conf.settings, and permissions.py imports
    # acl.service, so drop any earlier imports to re-execute them against the
    # stub.
    for name in ('cloudfile_ext.features', 'cloudfile_ext.acl.service',
                 'cloudfile_ext.permissions'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    importlib.import_module('cloudfile_ext.permissions')
    return importlib.import_module('cloudfile_ext.acl.service')


def test_effective_perm_forwards_to_apply_dir_acl(svc, monkeypatch):
    from cloudfile_ext.permissions import PermissionService

    calls = []

    def fake_apply(username, repo_id, path, native):
        calls.append((username, repo_id, path, native))
        return 'rw'

    monkeypatch.setattr(svc, 'apply_dir_acl', fake_apply)
    got = PermissionService.effective_perm('u@e.com', 'repo', '/a', 'rw')
    assert got == 'rw'
    assert calls == [('u@e.com', 'repo', '/a', 'rw')]


def test_can_manage_forwards_to_service_can_manage(svc, monkeypatch):
    from cloudfile_ext.permissions import PermissionService

    calls = []

    def fake_can_manage(username, repo_id, path):
        calls.append((username, repo_id, path))
        return True

    monkeypatch.setattr(svc, 'can_manage', fake_can_manage)
    assert PermissionService.can_manage('u@e.com', 'repo', '/a') is True
    assert calls == [('u@e.com', 'repo', '/a')]


def test_effective_perm_matches_canonical_behavior(svc, monkeypatch):
    from cloudfile_ext.permissions import PermissionService

    monkeypatch.setattr(svc, 'is_enabled', lambda name: True)
    deny = [{'path': '/secret', 'subject_type': 'user',
             'subject': 'u@e.com', 'permission': 'none', 'inherit': 1}]
    monkeypatch.setattr(svc, '_load_rules', lambda repo_id: deny)
    monkeypatch.setattr(svc, '_load_subjects',
                        lambda username: resolver.subject_set(username))

    # denying rule vetoes, grant path keeps the native
    assert PermissionService.effective_perm(
        'u@e.com', 'repo', '/secret', 'rw') is None
    assert PermissionService.effective_perm(
        'u@e.com', 'repo', '/open', 'rw') == 'rw'

    # switch off: native passes through unchanged
    monkeypatch.setattr(svc, 'is_enabled', lambda name: False)
    assert PermissionService.effective_perm(
        'u@e.com', 'repo', '/secret', 'rw') == 'rw'


def test_can_manage_matches_canonical_behavior(svc, monkeypatch):
    from cloudfile_ext.permissions import PermissionService

    monkeypatch.setattr(svc, '_is_library_admin', lambda u, r: False)
    monkeypatch.setattr(svc, 'is_enabled', lambda name: True)
    monkeypatch.setattr(svc, '_load_admin_rules', lambda repo_id: [
        {'path': '/a', 'subject_type': 'user', 'subject': 'u@e.com',
         'inherit': 1}])
    monkeypatch.setattr(svc, '_load_subjects',
                        lambda username: resolver.subject_set(username))

    assert PermissionService.can_manage('u@e.com', 'repo', '/a/b') is True
    assert PermissionService.can_manage('u@e.com', 'repo', '/other') is False
