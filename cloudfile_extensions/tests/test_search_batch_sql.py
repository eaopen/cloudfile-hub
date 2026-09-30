"""Search -> 4A -> real MariaDB candidates and C final object decisions."""
import os
from unittest.mock import Mock

import pytest

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.cursor import SearchCursorStore
from cloudfile_extensions.search.meilisearch import MeilisearchCandidates
from cloudfile_extensions.search.service import ResourceSearchService
from cloudfile_extensions.tests import test_resource_batch_sql as fixtures


@pytest.fixture
def database():
    if not os.environ.get('CF_TEST_DB_PORT') or not os.environ.get('CF_TEST_ACL_LIBRARY'):
        pytest.skip('requires isolated MariaDB and compiled C policy core')
    value = fixtures.ResourceBatchSQLTest()
    value.setUp()
    try:
        yield value
    finally:
        value.tearDown()


def service(database, refs):
    backend = object.__new__(MeilisearchCandidates)
    backend.page = Mock(return_value=dict(references=refs, next_offset=None))
    cursors = object.__new__(SearchCursorStore)
    return ResourceSearchService(database.service, backend, cursors,
        version_reader=lambda repo: dict(ready=True, policy_revision='p', index_generation='g'))


@pytest.mark.parametrize('count', [1, 20, 50, 100])
def test_real_c_search_batch_sizes_and_sparse_identity(database, count):
    refs = database.references(count)
    result = service(database, refs).query(dict(repo_id=refs[0]['repo_id'], q='item', limit=count))
    assert len(result['items']) == count
    assert database.core.evaluate.call_count == count
    assert all(item['annotation']['uid'] is None for item in result['items'])


def test_real_c_file_deny_ancestor_hidden_and_mixed_results(database):
    refs = database.references(4)
    database.rule(refs[0], 'none')
    hidden = {**refs[1], 'path': '/hidden', 'kind': 'dir'}
    database.rule(hidden, 'invisible', True)
    database.rule({**hidden, 'path': '/hidden/open'}, 'rw', True)
    refs[1] = {**refs[1], 'path': '/hidden/open/file'}
    result = service(database, [*refs, refs[2]]).query(dict(repo_id=refs[0]['repo_id'], q='item'))
    assert [item['reference'] for item in result['items']] == refs[2:]
    assert database.core.evaluate.call_count == 4
    assert database.lifecycle.call_count == 2


def test_epoch_change_inside_search_reader_aborts_and_rolls_back(database):
    refs = database.references(1)
    def reader(cursor, ref):
        cursor.execute('INSERT INTO cf_test_reader_effect VALUES(1)')
        database.context = {**database.context, 'context_epoch': 'changed'}
        return fixtures.ResourceEvidence('birth')
    database.lifecycle.side_effect = reader
    with pytest.raises(ContractError):
        service(database, refs).query(dict(repo_id=refs[0]['repo_id'], q='item'))
    with database.connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM cf_test_reader_effect')
        assert cursor.fetchone()[0] == 0
