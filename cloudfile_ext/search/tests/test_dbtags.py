# -*- coding: utf-8 -*-
"""Built-in tag backend: predicates, degradation rules, hit shape.

Django-free like the rest of cloudfile_ext's tests -- the provider takes an
injected repository, so no database is needed.
"""

import importlib
import sys
import types

import pytest

from cloudfile_ext import search_query
from cloudfile_ext.search.backends import dbtags


class FakeRepo(object):
    def __init__(self, id_, owner='owner@example.com'):
        self.id = id_
        self.owner = owner


class FakeRepository(object):
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def find_rows(self, repo_ids, tag_names, with_dirents=False):
        self.calls.append({
            'repo_ids': list(repo_ids),
            'tag_names': list(tag_names),
            'with_dirents': with_dirents,
        })
        return [dict(row) for row in self.rows]


def filters(*specs):
    return search_query.parse([
        {'field': f, 'op': op, 'value': value} for f, op, value in specs
    ])


def row(path, name=None, tags=(), is_dir=False, repo_id='repo-1',
        size=None, mtime=None):
    return {
        'repo_id': repo_id,
        'path': path,
        'name': name or path.rsplit('/', 1)[-1],
        'is_dir': is_dir,
        'tags': list(tags),
        'size': size,
        'mtime': mtime,
    }


def provider(rows):
    return dbtags.DbTagsProvider(repository=FakeRepository(rows))


# -- predicate helpers -------------------------------------------------------

def test_supported_ops_cover_exact_and_substring():
    assert search_query.IN in dbtags.SUPPORTED_OPS
    assert search_query.EQ in dbtags.SUPPORTED_OPS
    assert search_query.CONTAINS in dbtags.SUPPORTED_OPS
    # A metadata-only operator must be refused, not ignored.
    assert search_query.GT not in dbtags.SUPPORTED_OPS


def test_tag_names_collects_and_dedupes():
    parsed = filters(('tags', 'in', ['A', 'B']), ('tags', 'eq', 'A'),
                     ('creator', 'in', ['x@example.com']))
    assert dbtags.tag_names(parsed) == ['A', 'B']


def test_matches_tag_predicates_semantics():
    parsed = filters(('tags', 'in', ['UG12']))
    assert dbtags.matches_tag_predicates(['UG12', 'other'], parsed)
    assert not dbtags.matches_tag_predicates(['UG7'], parsed)

    contains = filters(('tags', 'contains', ['UG']))
    assert dbtags.matches_tag_predicates(['SYS_UGVER_UG12'], contains)
    assert not dbtags.matches_tag_predicates(['SYS_CAD_NX'], contains)

    both = filters(('tags', 'in', ['UG12']), ('tags', 'in', ['CAD']))
    assert not dbtags.matches_tag_predicates(['UG12'], both)


def test_matched_tag_names_reports_only_hits():
    parsed = filters(('tags', 'in', ['UG12']))
    assert dbtags.matched_tag_names(['UG12', 'CAD'], parsed) == ['UG12']


def test_matches_creator():
    assert dbtags.matches_creator('a@x.com', filters(('creator', 'in', ['a@x.com'])))
    assert not dbtags.matches_creator('b@x.com', filters(('creator', 'in', ['a@x.com'])))
    assert dbtags.matches_creator('a@x.com', filters(('creator', 'contains', ['@x.'])))


def test_matches_keyword_and_search_path():
    r = row('/docs/design.docx', name='design.docx')
    assert dbtags.matches_keyword(r, 'design')
    assert dbtags.matches_keyword(r, 'docs')
    assert not dbtags.matches_keyword(r, 'design', filename_only=True) is False
    assert not dbtags.matches_keyword(r, 'nope')
    assert dbtags.matches_search_path(r, '/docs')
    assert not dbtags.matches_search_path(r, '/other')


def test_matches_obj_desc_suffix_type_and_missing_data():
    assert dbtags.matches_obj_desc(row('/a.docx'), {'suffixes': ['docx']}) == (True, False)
    assert dbtags.matches_obj_desc(row('/a.pdf'), {'suffixes': ['docx']}) == (True, False)
    # A directory never matches a file suffix filter.
    assert dbtags.matches_obj_desc(
        row('/folder', is_dir=True), {'suffixes': ['docx']}) == (True, False)
    assert dbtags.matches_obj_desc(
        row('/folder', is_dir=True), {'obj_type': 'dir'}) == (True, False)
    assert dbtags.matches_obj_desc(row('/a.docx'), {'obj_type': 'dir'}) == (True, False)
    # size/time need the dirent: absent data is reported, never guessed.
    assert dbtags.matches_obj_desc(row('/a.docx'), {'size_range': (1, 2)}) == (False, True)
    assert dbtags.matches_obj_desc(
        row('/a.docx', size=5), {'size_range': (1, 10)}) == (True, False)
    assert dbtags.matches_obj_desc(
        row('/a.docx', size=50), {'size_range': (1, 10)}) == (True, False)
    assert dbtags.needs_dirents({'time_range': (1, 2)}) is True
    assert dbtags.needs_dirents({'suffixes': ['docx']}) is False


# -- provider ---------------------------------------------------------------

def test_search_returns_hits_and_total_with_matched_tags():
    rows = [
        row('/docs/a.prt', tags=['SYS_UGVER_UG12', 'CAD'], repo_id='repo-1'),
        row('/docs/b.prt', tags=['SYS_UGVER_UG7'], repo_id='repo-1'),
        row('/other/c.prt', tags=['SYS_UGVER_UG12'], repo_id='repo-1'),
    ]
    hits, total = provider(rows).search_files(
        {'repo-1': FakeRepo('repo-1')}, None, '', {}, 0, 10,
        filters=[{'field': 'tags', 'op': 'in', 'value': ['SYS_UGVER_UG12']}])

    assert total == 2
    assert [h['fullpath'] for h in hits] == ['/docs/a.prt', '/other/c.prt']
    assert hits[0]['tags'] == ['SYS_UGVER_UG12', 'CAD']
    assert hits[0]['matched_tags'] == ['SYS_UGVER_UG12']
    assert hits[0]['repo_id'] == 'repo-1'


def test_search_pages_deterministically():
    rows = [row('/docs/%s.prt' % chr(ord('a') + i), tags=['T']) for i in range(5)]
    p = provider(rows)
    first, total = p.search_files({'repo-1': FakeRepo('repo-1')}, None, '', {}, 0, 2,
                                  filters=[{'field': 'tags', 'op': 'in', 'value': ['T']}])
    second, _ = p.search_files({'repo-1': FakeRepo('repo-1')}, None, '', {}, 2, 2,
                               filters=[{'field': 'tags', 'op': 'in', 'value': ['T']}])
    assert total == 5
    assert [h['fullpath'] for h in first] == ['/docs/a.prt', '/docs/b.prt']
    assert [h['fullpath'] for h in second] == ['/docs/c.prt', '/docs/d.prt']


def test_search_includes_directories_user_tags_cover_folders():
    rows = [row('/folder', is_dir=True, tags=['项目']),
            row('/folder/a.txt', tags=['项目'])]
    hits, total = provider(rows).search_files(
        {'repo-1': FakeRepo('repo-1')}, None, '', {}, 0, 10,
        filters=[{'field': 'tags', 'op': 'in', 'value': ['项目']}])
    assert total == 2
    assert sorted(h['fullpath'] for h in hits) == ['/folder', '/folder/a.txt']
    assert hits[0]['size'] is None


def test_search_applies_keyword_creator_and_path():
    rows = [row('/docs/design.prt', tags=['T']),
            row('/docs/other.prt', tags=['T']),
            row('/docs/design.prt', tags=['T'], repo_id='repo-2')]
    repos = {'repo-1': FakeRepo('repo-1', owner='me@x.com'),
             'repo-2': FakeRepo('repo-2', owner='other@x.com')}
    hits, total = provider(rows).search_files(
        repos, '/docs', 'design', {}, 0, 10,
        filters=[{'field': 'tags', 'op': 'in', 'value': ['T']},
                 {'field': 'creator', 'op': 'in', 'value': ['me@x.com']}])
    assert total == 1
    assert hits[0]['fullpath'] == '/docs/design.prt'


def test_search_returns_empty_without_repos_or_tags():
    p = provider([row('/a', tags=['T'])])
    assert p.search_files({}, None, '', {}, 0, 10,
                          filters=[{'field': 'tags', 'op': 'in', 'value': ['T']}]) == ([], 0)


def test_search_refuses_size_filter_it_cannot_evaluate():
    rows = [row('/docs/a.prt', tags=['T'])]
    with pytest.raises(search_query.UnsupportedFilter):
        provider(rows).search_files(
            {'repo-1': FakeRepo('repo-1')}, None, '', {'size_range': (1, 10)}, 0, 10,
            filters=[{'field': 'tags', 'op': 'in', 'value': ['T']}])


def test_repository_asked_with_dirents_only_when_needed():
    # mtime is what the repository fills in when with_dirents=True; the tag
    # tables themselves cannot answer a time condition.
    rows = [row('/docs/a.prt', tags=['T'], mtime=5)]
    p = provider(rows)
    p.search_files({'repo-1': FakeRepo('repo-1')}, None, '', {}, 0, 10,
                   filters=[{'field': 'tags', 'op': 'in', 'value': ['T']}])
    p.search_files({'repo-1': FakeRepo('repo-1')}, None, '', {'time_range': (1, 10)}, 0, 10,
                   filters=[{'field': 'tags', 'op': 'in', 'value': ['T']}])
    assert p._repository.calls[0]['with_dirents'] is False
    assert p._repository.calls[1]['with_dirents'] is True


# -- hooks routing (the degradation contract) --------------------------------
#
# Why this stubs django.conf instead of using django.test: the shared checks
# install pytest and nothing else, so a Django-dependent test would be skipped
# there and read as coverage while providing none (same reasoning as
# cloudfile_ext/tests/test_providers.py, whose stub fixture this mirrors).


class FakeHooksProvider(object):
    #: The provider contract: a backend declares the operators it can honour,
    #: and hooks refuses the query rather than dropping an undeclared one.
    supported_filter_ops = dbtags.SUPPORTED_OPS

    def __init__(self):
        self.calls = []

    def search_files(self, repos_map, search_path, keyword, obj_desc, start,
                     size, org_id=None, search_filename_only=False, filters=None):
        self.calls.append({'keyword': keyword, 'filters': filters})
        return ([{'repo_id': 'repo-1', 'fullpath': '/a.prt'}], 1)


@pytest.fixture
def hooks_mod(monkeypatch):
    """Import cloudfile_ext.hooks against a stub settings object."""
    conf = types.ModuleType('django.conf')
    conf.settings = types.SimpleNamespace(
        CF_PROVIDER_SEARCH='', CF_SEARCH_DB_FALLBACK=True)
    django = types.ModuleType('django')
    django.conf = conf
    monkeypatch.setitem(sys.modules, 'django', django)
    monkeypatch.setitem(sys.modules, 'django.conf', conf)
    for name in ('cloudfile_ext.providers', 'cloudfile_ext.registry',
                 'cloudfile_ext.hooks'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    import cloudfile_ext
    for attr in ('providers', 'registry', 'hooks'):
        monkeypatch.delattr(cloudfile_ext, attr, raising=False)
    return types.SimpleNamespace(
        hooks=importlib.import_module('cloudfile_ext.hooks'),
        settings=conf.settings)


def test_hooks_route_tag_filter_to_builtin_backend_when_no_provider(hooks_mod, monkeypatch):
    hooks = hooks_mod.hooks
    fake = FakeHooksProvider()
    monkeypatch.setattr(hooks, '_db_fallback_enabled', lambda: True)
    monkeypatch.setattr(hooks, '_db_provider', lambda: fake)
    monkeypatch.setattr(hooks.registry, 'active_search_provider', lambda: None)

    hits, total = hooks.search_files(
        {'repo-1': FakeRepo('repo-1')}, None, 'design', {}, 0, 10,
        filters=[{'field': 'tags', 'op': 'in', 'value': ['UG12']}])

    assert total == 1 and hits[0]['fullpath'] == '/a.prt'
    # Parsed, and only the requested predicate reached the backend.
    assert [f.field for f in fake.calls[0]['filters']] == ['tags']


def test_hooks_refuse_filters_when_fallback_off(hooks_mod, monkeypatch):
    hooks = hooks_mod.hooks
    monkeypatch.setattr(hooks, '_db_fallback_enabled', lambda: False)
    monkeypatch.setattr(hooks.registry, 'active_search_provider', lambda: None)

    with pytest.raises(search_query.UnsupportedFilter):
        hooks.search_files({'repo-1': FakeRepo('repo-1')}, None, '', {}, 0, 10,
                           filters=[{'field': 'tags', 'op': 'in', 'value': ['UG12']}])


def test_hooks_leave_plain_keyword_search_to_native(hooks_mod, monkeypatch):
    hooks = hooks_mod.hooks
    monkeypatch.setattr(hooks, '_db_fallback_enabled', lambda: True)
    monkeypatch.setattr(hooks.registry, 'active_search_provider', lambda: None)

    # No filters -> None means "let Seahub's own backend answer".
    assert hooks.search_files({'repo-1': FakeRepo('repo-1')}, None, 'abc', {},
                              0, 10) is None


def test_search_backend_state_reports_degradation(hooks_mod, monkeypatch):
    hooks = hooks_mod.hooks
    monkeypatch.setattr(hooks, '_native_search_available', lambda: False)
    monkeypatch.setattr(hooks, '_db_fallback_enabled', lambda: True)
    monkeypatch.setattr(hooks, '_db_provider', lambda: FakeHooksProvider())
    assert hooks.search_backend_state() == 'db-tags'

    monkeypatch.setattr(hooks, '_db_provider', lambda: None)
    assert hooks.search_backend_state() == 'none'


def test_search_backend_state_prefers_native_when_elasticsearch_exists(hooks_mod, monkeypatch):
    hooks = hooks_mod.hooks
    monkeypatch.setattr(hooks, '_native_search_available', lambda: True)
    monkeypatch.setattr(hooks, '_db_fallback_enabled', lambda: True)
    monkeypatch.setattr(hooks, '_db_provider', lambda: FakeHooksProvider())
    # An ES-backed deployment keeps answering full text: the fallback must not
    # hijack it.
    assert hooks.search_backend_state() == 'native'
