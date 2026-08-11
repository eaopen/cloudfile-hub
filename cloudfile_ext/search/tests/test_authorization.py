# -*- coding: utf-8 -*-
"""Red tests for authorization-before-observability search pagination.

Plan 01-03 implements ``cloudfile_ext.search.authorization``. These tests pin
its backend-independent contract first: SeaSearch and Meilisearch supply raw
candidates, while one shared scanner applies the current ACL before snippets,
serialization, totals, pagination, or cache entries can become observable.
"""

import importlib.util
import json
import os

import pytest


BACKENDS = ('seasearch', 'meilisearch')


def _docker_root():
    here = os.path.dirname(os.path.abspath(__file__))
    hub_root = os.path.normpath(os.path.join(here, '..', '..', '..'))
    return os.path.join(os.path.dirname(hub_root), 'cloudfile-docker')


def _shared_cases():
    path = os.path.join(_docker_root(), 'tests', 'e2e', 'search_matrix.py')
    spec = importlib.util.spec_from_file_location('cf_search_matrix_cases', path)
    if spec is None or spec.loader is None:
        pytest.fail('cannot load shared search authorization cases at %s' % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AUTHORIZATION_CASES


def _authorization_module():
    try:
        from cloudfile_ext.search import authorization
        return authorization
    except ImportError as exc:
        pytest.fail(
            'cloudfile_ext.search.authorization is not implemented yet '
            '(Wave 3 plan 01-03 delivers authorize_search_page). '
            'Underlying ImportError: %s' % exc)


def _candidate(candidate_id, allowed):
    visibility = 'visible' if allowed else 'hidden'
    return {
        'id': candidate_id,
        'repo_id': 'repo-a',
        'name': '%s-name-%s.txt' % (visibility, candidate_id),
        'path': '/%s/path/%s.txt' % (visibility, candidate_id),
        'content': '%s-content-%s' % (visibility, candidate_id),
        'allowed': allowed,
    }


class FakeBackend(object):
    def __init__(self, name, candidates):
        self.name = name
        self.candidates = list(candidates)
        self.calls = []

    def fetch(self, offset, limit):
        self.calls.append((offset, limit))
        return self.candidates[offset:offset + limit]


class ObservabilityProbe(object):
    def __init__(self):
        self.snippets = []
        self.serialized = []

    def snippet(self, candidate):
        self.snippets.append(candidate['id'])
        return 'snippet:' + candidate['content']

    def serialize(self, candidate, snippet):
        self.serialized.append(candidate['id'])
        return {
            'id': candidate['id'],
            'name': candidate['name'],
            'path': candidate['path'],
            'snippet': snippet,
        }


def _scan(backend_name, case, revision=42, cache=None, cache_key='query'):
    authorization = _authorization_module()
    candidates = [_candidate(*entry) for entry in case['candidates']]
    backend = FakeBackend(backend_name, candidates)
    probe = ObservabilityProbe()
    result = authorization.authorize_search_page(
        fetch_batch=backend.fetch,
        authorize_candidate=lambda item: item['allowed'],
        serialize_candidate=probe.serialize,
        make_snippet=probe.snippet,
        page=case['page'],
        per_page=case['per_page'],
        batch_size=2,
        revision=revision,
        cache=cache,
        cache_key=cache_key,
    )
    return result, backend, probe


@pytest.mark.parametrize('backend_name', BACKENDS)
@pytest.mark.parametrize('case', _shared_cases(), ids=lambda case: case['name'])
def test_both_backends_use_shared_authorized_pagination_cases(backend_name,
                                                               case):
    result, backend, probe = _scan(backend_name, case)
    assert tuple(item['id'] for item in result['results']) == \
        case['expected_ids']
    assert result['total'] == case['expected_total']
    assert result['has_more'] is case['expected_has_more']

    hidden = {candidate_id for candidate_id, allowed in case['candidates']
              if not allowed}
    assert hidden.isdisjoint(probe.snippets)
    assert hidden.isdisjoint(probe.serialized)

    # An all-hidden batch must not terminate the scan. Correctness-first
    # over-fetch continues until the authorized page and exact total are known.
    if case['name'] == 'all-hidden-first-batch':
        assert len(backend.calls) >= 2


@pytest.mark.parametrize('backend_name', BACKENDS)
def test_hidden_fields_never_reach_response_or_cache(backend_name):
    case = _shared_cases()[0]
    cache = {}
    result, _backend, probe = _scan(backend_name, case, cache=cache)

    observable = json.dumps({'response': result, 'cache': cache}, sort_keys=True)
    assert 'hidden-name' not in observable
    assert '/hidden/path' not in observable
    assert 'hidden-content' not in observable
    assert all(not item.startswith('hidden-') for item in probe.snippets)


@pytest.mark.parametrize('backend_name', BACKENDS)
def test_revision_change_invalidates_cached_authorized_answer(backend_name):
    case = {
        'page': 1,
        'per_page': 10,
        'candidates': (('secret', True),),
    }
    cache = {}
    first, _backend, _probe = _scan(
        backend_name, case, revision=42, cache=cache, cache_key='same-query')
    assert [item['id'] for item in first['results']] == ['secret']
    assert cache, 'authorized results must be cached only after ACL filtering'
    assert any('42' in repr(key) for key in cache), (
        'the ACL revision must participate in every authorized cache key')

    revoked = dict(case)
    revoked['candidates'] = (('secret', False),)
    second, _backend, probe = _scan(
        backend_name, revoked, revision=43, cache=cache,
        cache_key='same-query')
    assert second == {'results': [], 'total': 0, 'has_more': False}
    assert probe.snippets == []
    assert any('43' in repr(key) for key in cache), (
        'a revoke must create/use a new revision-scoped cache key')
    assert 'hidden-name-secret' not in json.dumps(cache, sort_keys=True)


@pytest.mark.parametrize('backend_name', BACKENDS)
def test_provider_restart_does_not_restore_revoked_observables(backend_name):
    case = {
        'page': 1,
        'per_page': 10,
        'candidates': (('secret', False), ('public', True)),
    }
    cache = {}

    before, backend, _probe = _scan(
        backend_name, case, revision=44, cache=cache,
        cache_key='restart-query')
    restarted, new_backend, _probe = _scan(
        backend_name, case, revision=44, cache=cache,
        cache_key='restart-query')

    assert backend is not new_backend
    assert before == restarted
    assert [item['id'] for item in restarted['results']] == ['public']
    assert 'hidden-name-secret' not in json.dumps(restarted, sort_keys=True)
