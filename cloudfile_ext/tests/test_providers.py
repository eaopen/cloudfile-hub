# -*- coding: utf-8 -*-
"""Provider selection semantics.

Why this stubs django.conf instead of using django.test:

    The shared checks (cloudfile-docker/tools/run-checks.sh) install pytest and
    nothing else -- no Seahub requirements, no Django. A test that needs Django
    would be skipped there and in CI, and a check that never runs reads as
    coverage while providing none. Provider selection is pure logic over a
    settings object, so a stub is enough to exercise all of it honestly.
"""

import importlib
import sys
import types

import pytest


@pytest.fixture
def cf(monkeypatch):
    """Import cloudfile_ext.providers/registry against a stub settings object."""
    conf = types.ModuleType('django.conf')
    conf.settings = types.SimpleNamespace()
    django = types.ModuleType('django')
    django.conf = conf
    monkeypatch.setitem(sys.modules, 'django', django)
    monkeypatch.setitem(sys.modules, 'django.conf', conf)
    # Both the sys.modules entry and the attribute on the parent package have
    # to go. Dropping only the former leaves `from cloudfile_ext import
    # providers` returning the previous test's module -- still bound to that
    # test's stub settings -- while registry re-imports a fresh one, so the
    # two disagree about configuration and every selection test fails
    # mysteriously. importlib.import_module rebinds the parent attribute.
    for name in ('cloudfile_ext.providers', 'cloudfile_ext.registry'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    import cloudfile_ext
    for attr in ('providers', 'registry'):
        monkeypatch.delattr(cloudfile_ext, attr, raising=False)

    providers = importlib.import_module('cloudfile_ext.providers')
    registry = importlib.import_module('cloudfile_ext.registry')
    return types.SimpleNamespace(
        providers=providers, registry=registry, settings=conf.settings)


class FakeSearch(object):
    def search_files(self, *args):
        return ([{'repo_id': 'r', 'fullpath': '/a.txt'}], 1)


def test_setting_name_derives_from_kind(cf):
    """A new kind needs no edit to the baseline to become configurable."""
    assert cf.providers.setting_name('search') == 'CF_PROVIDER_SEARCH'
    assert cf.providers.setting_name('acl_rule_source') == \
        'CF_PROVIDER_ACL_RULE_SOURCE'
    assert cf.providers.setting_name('acl-rule-source') == \
        'CF_PROVIDER_ACL_RULE_SOURCE'


def test_nothing_selected_means_native_behaviour(cf):
    r = cf.registry.Registry()
    r.register_search_provider('meilisearch', FakeSearch())
    r.seal()
    # Registering must not activate: a build may ship several backends and the
    # deployment picks one. This is the "all switches off = native CE" rule.
    assert r.active_search_provider() is None


def test_selected_provider_is_returned(cf):
    r = cf.registry.Registry()
    chosen = FakeSearch()
    r.register_search_provider('meilisearch', chosen)
    r.register_search_provider('seasearch', FakeSearch())
    r.seal()
    cf.settings.CF_PROVIDER_SEARCH = 'meilisearch'
    assert r.active_search_provider() is chosen
    assert r.providers.names('search') == ['meilisearch', 'seasearch']


def test_unknown_name_fails_loudly(cf):
    """A typo must not degrade to the native backend.

    Silently serving Elasticsearch results to an operator who asked for
    meilisearch -- or serving no ACL rules to one who asked for an external
    source -- is worse than refusing.
    """
    r = cf.registry.Registry()
    r.register_search_provider('meilisearch', FakeSearch())
    r.seal()
    cf.settings.CF_PROVIDER_SEARCH = 'meilisearh'
    with pytest.raises(cf.providers.UnknownProvider) as exc:
        r.active_search_provider()
    # The message has to name what *is* available, or diagnosing it needs a
    # shell on the box.
    assert 'meilisearch' in str(exc.value)


def test_registration_closes_at_startup(cf):
    r = cf.registry.Registry()
    r.seal()
    with pytest.raises(RuntimeError):
        r.register_search_provider('late', FakeSearch())


def test_duplicate_name_is_rejected(cf):
    """Two capabilities claiming one name would make selection ambiguous."""
    r = cf.registry.Registry()
    r.register_search_provider('m', FakeSearch())
    with pytest.raises(ValueError):
        r.register_search_provider('m', FakeSearch())


def test_kinds_are_independent(cf):
    r = cf.registry.Registry()
    r.register_provider('acl_rule_source', 'local-db', 'LOCAL')
    r.register_provider('acl_rule_source', 'external-service', 'EXTERNAL')
    r.register_search_provider('meilisearch', FakeSearch())
    r.seal()
    cf.settings.CF_PROVIDER_ACL_RULE_SOURCE = 'external-service'
    assert r.providers.active('acl_rule_source') == 'EXTERNAL'
    # Selecting an ACL rule source must not switch search on.
    assert r.active_search_provider() is None


def test_describe_reports_selected_and_available(cf):
    r = cf.registry.Registry()
    r.register_search_provider('meilisearch', FakeSearch())
    r.register_provider('acl_rule_source', 'local-db', 'LOCAL')
    r.seal()
    cf.settings.CF_PROVIDER_SEARCH = 'meilisearch'
    assert r.providers.describe() == {
        'acl_rule_source': {'selected': '', 'available': ['local-db']},
        'search': {'selected': 'meilisearch', 'available': ['meilisearch']},
    }
