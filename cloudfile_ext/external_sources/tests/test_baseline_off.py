# -*- coding: utf-8 -*-
"""The iron rule, for this capability: switch off == native CE.

Merging a capability into ``dev`` is only safe because every CF_ENABLE_* is off
by default, so this is the invariant that makes the merge safe rather than a
nicety. It is checked here, at unit level, because the container gate
(tests/e2e/baseline.py) proves the *baseline* registers nothing -- it cannot
prove that about a capability that has since been merged in, since by then the
capability is part of the baseline build it is inspecting.

Three separate things are asserted, and the third is the one that would
otherwise rot silently:

1. With the switch off, ``register()`` contributes nothing to any hook.
2. Importing the package does not drag in Django, the database, or Seafile.
3. With the switch on, it *does* register -- otherwise assertions 1 and 2 would
   also pass on a capability that had been accidentally disabled outright, and
   the test would read as coverage while proving nothing.
"""

import sys
import types

import pytest


class FakeRegistry(object):
    """Records contributions instead of making them.

    A fake rather than the real Registry so a future hook cannot be added and
    silently escape this check: anything register() calls that is not listed
    here raises AttributeError, which fails the test.
    """

    def __init__(self):
        self.urls = []
        self.menu = []
        self.permission_checks = []
        self.periodic_tasks = []
        self.external_sources = {}
        self.providers = {}
        self.search_indexers = []
        self.file_op_hooks = []

    def register_urls(self, patterns):
        self.urls.extend(patterns)

    def register_menu(self, entry):
        self.menu.append(entry)

    def register_permission_check(self, func):
        self.permission_checks.append(func)

    def register_periodic_task(self, name, interval, func):
        self.periodic_tasks.append(name)

    def register_external_source_provider(self, source_type, provider):
        self.external_sources[source_type] = provider

    def register_provider(self, kind, name, provider):
        self.providers[(kind, name)] = provider

    def register_search_indexer(self, indexer):
        self.search_indexers.append(indexer)

    def register_file_op_hook(self, phase, func):
        self.file_op_hooks.append((phase, func))

    def contributed(self):
        """Everything this registry was asked to add, as one flat picture."""
        return {
            'urls': list(self.urls),
            'menu': list(self.menu),
            'permission_checks': list(self.permission_checks),
            'periodic_tasks': list(self.periodic_tasks),
            'external_sources': dict(self.external_sources),
            'providers': dict(self.providers),
            'search_indexers': list(self.search_indexers),
            'file_op_hooks': list(self.file_op_hooks),
        }


@pytest.fixture
def switched(monkeypatch):
    """Import the capability against a stub settings object.

    Same approach as cloudfile_ext/tests/test_providers.py: the shared checks
    install pytest and nothing else, so a test that needed real Django would be
    skipped in CI -- and a skipped check reads as coverage while providing none.
    """
    def _switched(on, search_provider=''):
        conf = types.ModuleType('django.conf')
        conf.settings = types.SimpleNamespace(
            CF_ENABLE_EXTERNAL_SOURCES=on,
            CF_PROVIDER_SEARCH=search_provider,
        )
        django = types.ModuleType('django')
        django.conf = conf
        urls = types.ModuleType('django.urls')
        urls.path = lambda pattern, view, name=None: (pattern, view, name)
        urls.re_path = lambda pattern, view, name=None: (pattern, view, name)
        django.urls = urls
        monkeypatch.setitem(sys.modules, 'django', django)
        monkeypatch.setitem(sys.modules, 'django.conf', conf)
        monkeypatch.setitem(sys.modules, 'django.urls', urls)
        for name in list(sys.modules):
            if name.startswith('cloudfile_ext.features'):
                monkeypatch.delitem(sys.modules, name, raising=False)

        from cloudfile_ext import external_sources
        registry = FakeRegistry()
        external_sources.register(registry)
        return registry

    return _switched


def test_switch_off_contributes_nothing(switched):
    """No routes, no backend, no task, no permission hook -- nothing at all.

    A single empty-dict assertion rather than eight, so that a hook added later
    is covered without anyone remembering to extend this test.
    """
    registry = switched(False)
    contributed = registry.contributed()
    assert all(not value for value in contributed.values()), contributed


def test_switch_off_does_not_import_the_database_layer(switched):
    """Off means the models are never even imported.

    Not cosmetic: models.py declares managed=False Django models, and importing
    it registers them with the app registry. On a deployment that never turns
    this capability on, that is work and surface area for nothing -- and the
    reason the imports are inside register() rather than at module scope, where
    they would be the obvious place to put them.
    """
    switched(False)
    assert 'cloudfile_ext.external_sources.models' not in sys.modules
    assert 'cloudfile_ext.external_sources.apis' not in sys.modules
    assert 'cloudfile_ext.external_sources.admin_apis' not in sys.modules


def test_importing_the_package_needs_no_django(monkeypatch):
    """The package must import with Django absent entirely.

    cloudfile-hub's AGENTS.md requires a capability's pure parts to be usable
    without Seahub. Here it also protects the security boundary: paths.py and
    authz.py are only mutation-testable standalone while nothing above them
    imports Django at module scope.
    """
    for name in list(sys.modules):
        if name.startswith('cloudfile_ext.external_sources') or \
                name.startswith('django'):
            monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = __builtins__['__import__'] if isinstance(__builtins__, dict) \
        else __builtins__.__import__

    def guarded(name, *args, **kwargs):
        if name == 'django' or name.startswith('django.'):
            raise AssertionError('importing the package pulled in %s' % name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr('builtins.__import__', guarded)

    import cloudfile_ext.external_sources  # noqa: F401
    import cloudfile_ext.external_sources.paths  # noqa: F401
    import cloudfile_ext.external_sources.authz  # noqa: F401


def test_switch_on_is_not_quiet(switched):
    """The control: with the switch on, register() must not be silently empty.

    Without this, the two checks above prove nothing -- a capability that had
    been disabled outright (register() returning early unconditionally, or its
    body deleted) would satisfy every one of them. This is what makes them mean
    "off is quiet" rather than "this code is dead".

    The assertion is "registers something *or* raises" rather than a count of
    routes, because the view modules import rest_framework and Seahub, and the
    shared checks (cloudfile-docker/tools/run-checks.sh) install pytest and
    nothing else. Demanding the full wiring here would make this a skipped test
    in the one environment where it actually runs -- and a silently skipped
    check is the failure mode this whole file exists to prevent.

    So: in a bare environment the switch being on gets far enough to try the
    imports and raises, and in a full one it registers. Both outcomes prove the
    guard let go. Only "returned quietly, registered nothing" fails, and that
    is exactly the regression worth catching.
    """
    try:
        registry = switched(True)
    except (ImportError, AttributeError):
        # Reached the view imports, so the guard is switch-driven. The full
        # wiring is asserted by the next test wherever the deps exist.
        return

    assert 'local-path' in registry.external_sources, registry.external_sources
    assert len(registry.urls) == 15, registry.urls


def test_switch_on_registers_the_backend_and_nothing_shared(switched,
                                                            monkeypatch):
    """Full wiring, with the DRF-dependent view modules stubbed out.

    Only the two view modules are faked -- the URL list, the backend
    registration and the switch logic are all the real thing. Stubbing them is
    honest here because what is being checked is *what register() contributes*,
    not what the views do; their behaviour is covered by their own tests and
    the capability gate.

    The last three assertions are the ones that matter for merging into ``dev``:
    turning this capability on must not add anything to a *shared* chain, so it
    cannot change behaviour for any other capability or for native CE paths.
    """
    for name in ('cloudfile_ext.external_sources.admin_apis',
                 'cloudfile_ext.external_sources.apis'):
        module = types.ModuleType(name)
        for attr in ('AdminExternalSourcesView', 'AdminExternalSourceView',
                     'AdminExternalSourceGrantsView', 'ExternalSourcesView',
                     'ExternalSourceDirView', 'ExternalSourceFileView'):
            setattr(module, attr, types.SimpleNamespace(as_view=lambda: None))
        monkeypatch.setitem(sys.modules, name, module)

    overlay = types.ModuleType('cloudfile_ext.external_sources.overlay_apis')
    overlay.ExternalOverlayView = types.SimpleNamespace(as_view=lambda: None)
    monkeypatch.setitem(sys.modules, overlay.__name__, overlay)

    search = types.ModuleType('cloudfile_ext.external_sources.search_apis')
    search.ExternalSourceSearchView = types.SimpleNamespace(as_view=lambda: None)
    monkeypatch.setitem(sys.modules, search.__name__, search)

    shadows = types.ModuleType('cloudfile_ext.external_sources.shadows')
    for attr in ('ExternalApi2FileView', 'ExternalDirView',
                 'ExternalFileDetailView', 'ExternalFileView',
                 'ExternalRepoView', 'ExternalReposView'):
        setattr(shadows, attr, types.SimpleNamespace(as_view=lambda: None))
    monkeypatch.setitem(sys.modules, shadows.__name__, shadows)

    views = types.ModuleType('cloudfile_ext.external_sources.views')
    views.external_sources_page = object()
    monkeypatch.setitem(sys.modules, views.__name__, views)

    registry = switched(True)

    assert 'local-path' in registry.external_sources
    assert len(registry.urls) == 15, registry.urls
    assert registry.permission_checks == []
    assert registry.periodic_tasks == []
    assert registry.menu == [{
        'key': 'external-sources',
        'label': 'External sources',
        'url': '/cloudfile/external-sources/',
        'feature': 'CF_ENABLE_EXTERNAL_SOURCES',
    }]


def test_meilisearch_registers_the_bounded_scanner(switched, monkeypatch):
    """The periodic scanner is opt-in and never starts under SeaSearch."""
    for name in ('cloudfile_ext.external_sources.admin_apis',
                 'cloudfile_ext.external_sources.apis'):
        module = types.ModuleType(name)
        for attr in ('AdminExternalSourcesView', 'AdminExternalSourceView',
                     'AdminExternalSourceGrantsView', 'ExternalSourcesView',
                     'ExternalSourceDirView', 'ExternalSourceFileView'):
            setattr(module, attr, types.SimpleNamespace(as_view=lambda: None))
        monkeypatch.setitem(sys.modules, name, module)

    for module_name, attrs in {
            'cloudfile_ext.external_sources.overlay_apis': ('ExternalOverlayView',),
            'cloudfile_ext.external_sources.search_apis': ('ExternalSourceSearchView',),
            'cloudfile_ext.external_sources.shadows': (
                'ExternalApi2FileView', 'ExternalDirView',
                'ExternalFileDetailView', 'ExternalFileView',
                'ExternalRepoView', 'ExternalReposView'),
    }.items():
        module = types.ModuleType(module_name)
        for attr in attrs:
            setattr(module, attr, types.SimpleNamespace(as_view=lambda: None))
        monkeypatch.setitem(sys.modules, module_name, module)

    views = types.ModuleType('cloudfile_ext.external_sources.views')
    views.external_sources_page = object()
    monkeypatch.setitem(sys.modules, views.__name__, views)
    scanner = types.ModuleType('cloudfile_ext.external_sources.scanner')
    scanner.TASK_NAME = 'external_source_scan'
    scanner.scan_tick = object()
    monkeypatch.setitem(sys.modules, scanner.__name__, scanner)

    registry = switched(True, 'meilisearch')
    assert registry.periodic_tasks == ['external_source_scan']
