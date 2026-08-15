# -*- coding: utf-8 -*-
"""MeilisearchProvider's query-translation and repo-scoping logic.

Django-free, like the rest of cloudfile_ext's tests: the shared checks
(cloudfile-docker/tools/run-checks.sh) install pytest and nothing else.
cloudfile_ext.search.backends.meilisearch only imports Django lazily inside
client_from_settings(), which none of these tests call -- a fake client is
injected instead, the same shape as FakeSearch in cloudfile_ext/tests/test_providers.py.
"""

import json

import pytest

from cloudfile_ext import search_query
from cloudfile_ext.search.backends import meilisearch


class FakeRepo(object):
    def __init__(self, id_):
        self.id = id_


class FakeClient(object):
    def __init__(self, response=None, raises=None):
        self.response = response if response is not None else {'hits': []}
        self.raises = raises
        self.calls = []

    def search(self, query, filter_expr, offset, limit, filename_only=False):
        self.calls.append({
            'query': query, 'filter_expr': filter_expr, 'offset': offset,
            'limit': limit, 'filename_only': filename_only,
        })
        if self.raises:
            raise self.raises
        return self.response


# -- _filter_expr ------------------------------------------------------------

def test_eq_and_ne_translate_to_meilisearch_comparison():
    eq = search_query.FieldFilter('project', search_query.EQ, 'Apollo')
    ne = search_query.FieldFilter('project', search_query.NE, 'Apollo')
    assert meilisearch._filter_expr(eq) == 'project = "Apollo"'
    assert meilisearch._filter_expr(ne) == 'project != "Apollo"'


def test_in_translates_to_meilisearch_in_with_a_json_array():
    f = search_query.FieldFilter('status', search_query.IN, ['draft', 'final'])
    assert meilisearch._filter_expr(f) == 'status IN ["draft", "final"]'


def test_exists_takes_no_value():
    f = search_query.FieldFilter('security_level', search_query.EXISTS)
    assert meilisearch._filter_expr(f) == 'security_level EXISTS'


def test_operator_without_a_template_is_refused():
    """Defensive: check_supported() already refuses this before the provider
    is called, given supported_filter_ops below. This guards against the two
    ever drifting apart."""
    f = search_query.FieldFilter('size', search_query.GT, 10)
    with pytest.raises(search_query.UnsupportedFilter):
        meilisearch._filter_expr(f)


def test_supported_filter_ops_matches_what_filter_expr_can_translate():
    assert meilisearch.MeilisearchProvider.supported_filter_ops == \
        frozenset(meilisearch._OP_TEMPLATES)


# -- _obj_desc_clauses ---------------------------------------------------

def test_obj_desc_translates_every_declared_field():
    clauses = meilisearch._obj_desc_clauses({
        'obj_type': 'file',
        'suffixes': ['pdf', 'docx'],
        'time_range': (100, 200),
        'size_range': (1, 2),
    })
    assert clauses == [
        'object_type = "file"',
        'extension IN ["pdf", "docx"]',
        'mtime >= 100',
        'mtime <= 200',
        'size >= 1',
        'size <= 2',
    ]


def test_obj_desc_omits_unset_fields():
    assert meilisearch._obj_desc_clauses({
        'obj_type': None, 'suffixes': None,
        'time_range': (None, None), 'size_range': (None, None),
    }) == []


def test_obj_desc_handles_none_and_empty():
    assert meilisearch._obj_desc_clauses(None) == []
    assert meilisearch._obj_desc_clauses({}) == []


# -- MeilisearchProvider.search_files ----------------------------------------

def test_empty_repos_map_short_circuits_without_calling_the_backend():
    client = FakeClient()
    hits, total = meilisearch.MeilisearchProvider(client=client).search_files(
        {}, None, 'q', None, 0, 10)
    assert (hits, total) == ([], 0)
    assert client.calls == []


def test_query_is_scoped_to_the_repos_the_caller_already_resolved():
    """Inherits Seahub's own permission-aware repo scoping: the provider must
    never widen the query beyond repos_map's keys (see
    cloudfile_ext.hooks.search_files's docstring)."""
    client = FakeClient()
    meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a'), 'repo-b': FakeRepo('repo-b')},
        None, 'q', None, 0, 10)
    filter_expr = client.calls[0]['filter_expr']
    assert 'repo_id IN ["repo-a", "repo-b"]' in filter_expr


def test_search_path_narrows_to_a_subtree_with_dirs():
    client = FakeClient()
    meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, '/项目/设计', 'q', None, 0, 10)
    # Meilisearch 1.10 has no STARTS WITH; the folder narrowing rides the
    # document's dirs array (ancestor paths) via an IN filter.
    assert 'dirs IN ["/项目/设计"]' in client.calls[0]['filter_expr']


def test_custom_filters_and_obj_desc_are_both_applied():
    client = FakeClient()
    filters = [search_query.FieldFilter('project', search_query.EQ, 'Apollo')]
    meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, None, 'q',
        {'obj_type': 'file', 'suffixes': None, 'time_range': (None, None),
         'size_range': (None, None)},
        0, 10, filters=filters)
    filter_expr = client.calls[0]['filter_expr']
    assert 'object_type = "file"' in filter_expr
    assert 'project = "Apollo"' in filter_expr


def test_search_filename_only_is_passed_through_to_the_client():
    client = FakeClient()
    meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, None, 'q', None, 0, 10,
        search_filename_only=True)
    assert client.calls[0]['filename_only'] is True


def test_hits_are_translated_to_the_search_files_contract():
    client = FakeClient(response={
        'hits': [{'repo_id': 'repo-a', 'path': '/a.txt', 'name': 'a.txt',
                  'size': 42}],
        'estimatedTotalHits': 7,
    })
    hits, total = meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, None, 'q', None, 0, 10)
    assert total == 7
    assert hits == [{'repo_id': 'repo-a', 'fullpath': '/a.txt',
                     'name': 'a.txt', 'size': 42, 'tags': [],
                     'matched_tags': []}]


def test_matched_tags_are_derived_from_highlighted_tag_values():
    """A tag hit must be distinguishable from a name hit: Meilisearch wraps
    the matched term inside a tag value with <em>, and the provider turns that
    back into clean tag names so the UI can label them 'matched tag'."""
    client = FakeClient(response={
        'hits': [{
            'repo_id': 'repo-a', 'path': '/a.txt', 'name': 'a.txt',
            'size': 42, 'tags': ['合同', '财务'],
            '_formatted': {'tags': ['<em>合同</em>', '财务']},
        }],
    })
    hits, total = meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, None, '合同', None, 0, 10)
    assert hits[0]['tags'] == ['合同', '财务']
    assert hits[0]['matched_tags'] == ['合同']


def test_no_highlight_means_no_matched_tags():
    """When the query matched the name (or content), not a tag, the tags come
    back unhighlighted and matched_tags stays empty -- never a false 'matched
    tag' label."""
    client = FakeClient(response={
        'hits': [{
            'repo_id': 'repo-a', 'path': '/合同.txt', 'name': '合同.txt',
            'size': 42, 'tags': ['财务'],
            '_formatted': {'tags': ['财务']},
        }],
    })
    hits, total = meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, None, '合同', None, 0, 10)
    assert hits[0]['matched_tags'] == []


def test_tag_and_creator_filters_translate_to_meilisearch_filters():
    """The advanced panel's tag/creator predicates ride the same structured
    filter vocabulary as any user-defined attribute; nothing backend-specific
    is needed beyond declaring the attributes filterable."""
    client = FakeClient()
    filters = [
        search_query.FieldFilter('tags', search_query.IN, ['合同', '财务']),
        search_query.FieldFilter('creator', search_query.EQ, 'a@e.com'),
    ]
    meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, None, 'q', None, 0, 10, filters=filters)
    filter_expr = client.calls[0]['filter_expr']
    assert 'tags IN ["合同", "财务"]' in filter_expr
    assert 'creator = "a@e.com"' in filter_expr


def test_backend_failure_returns_empty_results_instead_of_raising():
    """seahub.api2.views wraps search_files() in a bare except and would turn
    a raised exception into a 500; returning ([], 0) here instead means a
    Meilisearch outage degrades to an empty result page, matching how
    cloudfile_ext.hooks.search_files documents the same trade for
    UnknownProvider."""
    client = FakeClient(raises=meilisearch.MeilisearchError('boom'))
    hits, total = meilisearch.MeilisearchProvider(client=client).search_files(
        {'repo-a': FakeRepo('repo-a')}, None, 'q', None, 0, 10)
    assert (hits, total) == ([], 0)
