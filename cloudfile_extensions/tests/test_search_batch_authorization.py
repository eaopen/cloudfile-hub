"""Search consumes the real 4A batch; only native I/O/C are counted fixtures."""
from contextlib import contextmanager
from unittest.mock import Mock, patch

import pytest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.cursor import SearchCursorStore
from cloudfile_extensions.search.meilisearch import MeilisearchCandidates
from cloudfile_extensions.search.query_runtime import GuardedSearchRequest
from cloudfile_extensions.search.service import ResourceSearchService
from cloudfile_extensions.tests import test_resource_batch as fixtures


@pytest.fixture
def batch():
    fixture = fixtures.ResourceBatchTest()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


def search(batch, refs):
    backend = object.__new__(MeilisearchCandidates)
    backend.page = Mock(return_value=dict(references=refs, next_offset=100))
    cursors = object.__new__(SearchCursorStore)
    cursors.issue = Mock(return_value='opaque')
    versions = Mock(return_value=dict(ready=True, policy_revision='policy', index_generation='generation'))
    return ResourceSearchService(batch.service, backend, cursors, version_reader=versions)


@pytest.mark.parametrize('count', [1, 20, 50, 100])
def test_search_reuses_one_real_batch_with_bounded_loads(batch, count):
    refs = batch.refs(count)
    service = search(batch, refs)
    # Forbid both the old scalar loader and any Search-specific authorization.
    with patch.object(batch.service, 'resolve', side_effect=AssertionError('scalar resolve')):
        with patch.object(batch.service, 'batch_resolve', wraps=batch.service.batch_resolve) as resolve:
            result = service.query(dict(q='item', repo_id=refs[0]['repo_id'], limit=count))
    groups = (count + 19) // 20
    assert len(result['items']) == count
    assert resolve.call_count == 1
    assert batch.authority.core.evaluate.call_count == count
    assert batch.authority.native_qualification.read.call_count == groups
    assert batch.connection.counts['candidates_query'] == groups
    assert batch.connection.counts['resource_sql'] == groups * 5
    assert batch.connection.counts['tag_sql'] == groups * 8
    # Query preparation and its two publication-boundary epoch reads stay.
    assert batch.preparation.contexts.current.call_count == groups * 2 + 9


def test_duplicates_denials_deleted_and_moved_hits_preserve_candidate_offset(batch):
    refs = batch.refs(4)
    batch.denied.add(refs[1]['path'])
    batch.missing.update(ref['path'] for ref in refs[2:])
    service = search(batch, [refs[0], refs[1], refs[0], *refs[2:]])
    result = service.query(dict(q='item', repo_id=refs[0]['repo_id']))
    assert [item['reference'] for item in result['items']] == refs[:1]
    assert batch.authority.core.evaluate.call_count == 4
    assert batch.service.reader.call_count == 3
    assert service.cursors.issue.call_args.kwargs['offset'] == 100


@pytest.mark.parametrize('repo', [fixtures.uid(1), fixtures.uid(2)])
def test_independent_repo_requests_do_not_share_decisions(batch, repo):
    refs = batch.refs(2, repo=repo)
    service = search(batch, refs)
    assert len(service.query(dict(q='item', repo_id=repo))['items']) == 2
    assert all(call.args[0]['repo_id'] == repo for call in batch.authority.core.evaluate.call_args_list)


def test_foreign_repo_candidate_fails_before_loading(batch):
    refs = batch.refs(1, repo=fixtures.uid(2))
    with pytest.raises(ContractError):
        search(batch, refs).query(dict(q='item', repo_id=fixtures.uid(1)))
    batch.authority.core.evaluate.assert_not_called()


@pytest.mark.parametrize('field', ['policy_revision', 'index_generation'])
def test_publication_version_change_aborts_after_actual_batch(batch, field):
    refs = batch.refs(21)
    service = search(batch, refs)
    original = service.version_reader.return_value
    service.version_reader.side_effect = [original, {**original, field: 'changed'}]
    with pytest.raises(ContractError):
        service.query(dict(q='item', repo_id=refs[0]['repo_id']))
    assert batch.authority.core.evaluate.call_count == 21
    service.cursors.issue.assert_not_called()


def test_partial_batch_failure_rolls_back_and_cannot_publish_cursor(batch):
    refs = batch.refs(21)
    service = search(batch, refs)
    def lifecycle(cursor, ref):
        if ref == refs[-1]:
            raise RuntimeError('unavailable')
        return batch.lifecycle(cursor, ref)
    batch.service.reader.side_effect = lifecycle
    with pytest.raises(ContractError) as failure:
        service.query(dict(q='item', repo_id=refs[0]['repo_id']))
    assert failure.value.code == 'POLICY_UNAVAILABLE'
    assert not batch.connection.active
    assert batch.connection.events[-1] == 'rollback'
    service.cursors.issue.assert_not_called()


def test_response_scope_covers_batch_serialization_and_exit_failure(batch):
    refs = batch.refs(1)
    service = search(batch, refs)
    active = []
    @contextmanager
    def scope(resources, repo):
        active.append(repo)
        try:
            yield
            # A session/head revocation at the final scope boundary aborts the
            # response even though the batch itself already committed.
            raise ContractError('SEARCH_CHANGED', 'revoked', 503)
        finally:
            active.pop()
    def lifecycle(cursor, ref):
        assert active == [ref['repo_id']]
        return batch.lifecycle(cursor, ref)
    batch.service.reader.side_effect = lifecycle
    guarded = GuardedSearchRequest(service, scope)
    with pytest.raises(ContractError):
        with guarded.response(dict(q='item', repo_id=refs[0]['repo_id'])) as result:
            assert active and result['items']
    assert not active
