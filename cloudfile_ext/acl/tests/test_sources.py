# -*- coding: utf-8 -*-
"""ACL rule-source selection.

The invariant worth protecting: an unset CF_PROVIDER_ACL_RULE_SOURCE must
behave exactly as the system did before rule sources existed, and a name that
is designed but not yet built must fail loudly rather than resolve to an empty
table -- an empty cf_dir_acl looks like "no rules configured", not like "that
source is not implemented".

Django-free for the same reason as the other cloudfile_ext tests: the shared
checks install pytest only.
"""

import importlib
import sys
import types

import pytest


@pytest.fixture
def cf(monkeypatch):
    conf = types.ModuleType('django.conf')
    conf.settings = types.SimpleNamespace()
    django = types.ModuleType('django')
    django.conf = conf
    monkeypatch.setitem(sys.modules, 'django', django)
    monkeypatch.setitem(sys.modules, 'django.conf', conf)

    names = ('cloudfile_ext.providers', 'cloudfile_ext.registry',
             'cloudfile_ext.acl.sources')
    for name in names:
        monkeypatch.delitem(sys.modules, name, raising=False)
    import cloudfile_ext
    import cloudfile_ext.acl
    for attr in ('providers', 'registry'):
        monkeypatch.delattr(cloudfile_ext, attr, raising=False)
    monkeypatch.delattr(cloudfile_ext.acl, 'sources', raising=False)

    registry_mod = importlib.import_module('cloudfile_ext.registry')
    sources = importlib.import_module('cloudfile_ext.acl.sources')
    reg = registry_mod.Registry()
    sources.register(reg)
    return types.SimpleNamespace(sources=sources, registry=reg,
                                 settings=conf.settings)


def test_unset_means_local_database(cf):
    """Historical behaviour when the operator has configured nothing."""
    active = cf.sources.active(cf.registry)
    assert isinstance(active, cf.sources.LocalDatabaseSource)
    assert active.writable


def test_local_db_can_be_selected_explicitly(cf):
    cf.settings.CF_PROVIDER_ACL_RULE_SOURCE = cf.sources.LOCAL_DB
    assert cf.sources.active(cf.registry) is cf.sources._LOCAL


def test_local_sync_is_a_noop(cf):
    """Rules are written by the REST API; there is nothing upstream to pull."""
    assert cf.sources.active(cf.registry).sync()['synced'] == 0


def test_designed_but_unbuilt_source_refuses(cf):
    """external-service must not resolve to something that silently syncs nothing.

    A no-op stub would leave cf_dir_acl empty, and an empty table is
    indistinguishable from "no rules have been configured" -- so the operator
    would conclude ACL is broken rather than that the source is unimplemented.
    """
    from cloudfile_ext.providers import UnknownProvider

    cf.settings.CF_PROVIDER_ACL_RULE_SOURCE = cf.sources.EXTERNAL_SERVICE
    with pytest.raises(UnknownProvider) as exc:
        cf.sources.active(cf.registry)
    assert cf.sources.LOCAL_DB in str(exc.value)


def test_rule_source_kind_is_not_search(cf):
    """Selecting a rule source must not switch the search backend on."""
    cf.settings.CF_PROVIDER_ACL_RULE_SOURCE = cf.sources.LOCAL_DB
    assert cf.registry.active_search_provider() is None
