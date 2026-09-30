"""Transport, authorization isolation and protocol invariants without Django."""
import json
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloudfile_ext.legacy_tags.contract import request_body, MAX_BYTES
from cloudfile_ext.legacy_tags.service import resolve
from cloudfile_ext.search.access import SearchAccess
from cloudfile_ext.search.native_many import NativePermissionMany
from cloudfile_ext.search.bounded import SearchFailure
from cloudfile_ext.search.tests.test_search_access import snapshot, rule

REPO = '11111111-1111-4111-8111-111111111111'


def body(items):
    return json.dumps(dict(version=1, repo_id=REPO, items=items), ensure_ascii=False).encode()


def authority(state=None, decision=lambda path: 'rw'):
    calls = dict(transport=0, scalar=0, hooks=0)
    def rpc(raw):
        request = json.loads(raw)
        calls['transport'] += 1
        calls['scalar'] += len(request['paths'])
        return json.dumps(dict(version=1, repo_id=REPO, user='alice', items=[
            dict(path=p, permission=decision(p)) for p in request['paths']]))
    def hook(*args):
        calls['hooks'] += 1
        return args[-1]
    return SearchAccess(lambda: state if state is not None else snapshot(), None,
        native_many=NativePermissionMany(REPO, 'alice', rpc, hook)), calls


@pytest.mark.parametrize('count', [1, 20, 50, 100, 200])
def test_bounded_groups_separate_transport_and_decisions(count):
    totals = dict(transport=0, scalar=0, hooks=0)
    loads = []
    for start in range(0, count, 50):
        items = [('/a/f' + str(i), False) for i in range(start, min(count, start + 50))]
        access, calls = authority()
        def load(allowed):
            loads.append(allowed)
            return {key: [] for key in allowed}
        result = resolve(REPO, items, access, lambda *args: SimpleNamespace(mode=stat.S_IFREG), load)
        assert [i['path'] for i in result['items']] == [p for p, _ in items]
        access.assert_current()
        for key in totals: totals[key] += calls[key]
    groups = (count + 49) // 50
    assert len(loads) == groups
    assert totals['scalar'] == 2 * (count + 2 * groups)
    assert totals['hooks'] == totals['scalar']
    assert totals['transport'] == (2 if count < 49 else 4 * groups)


def test_hidden_folder_file_denials_only_load_authorized_exact_objects():
    state = snapshot([rule('/a/file', 'none', inherit=False), rule('/a/hidden', 'invisible'),
                      rule('/a/hidden/open', 'rw')])
    state['native_rules'] = [rule('/native', 'invisible')]
    access, _ = authority(state)
    items = [(p, False) for p in ['/a/good', '/a/file', '/a/hidden/open/file', '/native/file', '/missing']]
    lookup = Mock(side_effect=lambda p, d: None if p == '/missing' else SimpleNamespace(mode=stat.S_IFREG))
    store = Mock(side_effect=lambda allowed: {key: [] for key in allowed})
    result = resolve(REPO, items, access, lookup, store)
    assert [i['status'] for i in result['items']] == ['OK', 'DENIED', 'DENIED', 'DENIED', 'NOT_FOUND']
    store.assert_called_once_with([('/a/good', False)])
    assert lookup.call_count == 2
    assert all(i['tags'] is None for i in result['items'][1:])
    access.assert_current()


def test_duplicates_restore_independent_mutable_slots_and_only_load_once():
    access, _ = authority()
    store = Mock(side_effect=lambda items: {key: [dict(id=1, name='legacy', creator='u')] for key in items})
    result = resolve(REPO, [('/a', False), ('/b', False), ('/a', False)], access,
        lambda *args: SimpleNamespace(mode=stat.S_IFREG), store)
    store.assert_called_once_with([('/a', False), ('/b', False)])
    result['items'][0]['tags'][0]['name'] = 'changed'
    assert result['items'][2]['tags'][0]['name'] == result['items'][1]['tags'][0]['name'] == 'legacy'


def test_per_object_provider_error_is_not_no_tags_and_shared_db_error_is_fatal():
    access, _ = authority()
    lookup = Mock(side_effect=[RuntimeError(), SimpleNamespace(mode=stat.S_IFREG)])
    result = resolve(REPO, [('/a', False), ('/b', False)], access, lookup, lambda items: {key: [] for key in items})
    assert [i['status'] for i in result['items']] == ['FAILED', 'OK']
    access, _ = authority()
    with pytest.raises(RuntimeError):
        resolve(REPO, [('/a', False)], access, lambda *args: SimpleNamespace(mode=stat.S_IFREG), Mock(side_effect=RuntimeError()))


def test_revoke_after_tag_load_never_makes_first_pass_authoritative():
    state = snapshot()
    access, _ = authority(state)
    result = resolve(REPO, [('/a', False)], access, lambda *args: SimpleNamespace(mode=stat.S_IFREG), lambda items: {key: [] for key in items})
    assert result['items'][0]['status'] == 'OK'
    state['state']['active'] = False
    with pytest.raises(SearchFailure): access.assert_current()


@pytest.mark.parametrize('path', ['relative', '/a//b', '/a/../b', '/a\x00b', '/' + '中' * 1366])
def test_malformed_path(path):
    with pytest.raises(Exception): request_body(body([dict(path=path, is_dir=False)]))


def test_request_item_byte_and_identity_boundaries():
    values = [dict(path='/a/' + str(i), is_dir=False) for i in range(50)]
    assert len(request_body(body(values))[1]) == 50
    with pytest.raises(ValueError): request_body(body(values + values[:1]))
    request = body(values)
    assert request_body(request + b' ' * (MAX_BYTES - len(request)))[0] == REPO
    with pytest.raises(ValueError): request_body(request + b' ' * (MAX_BYTES + 1 - len(request)))
    for raw in [b'{"version":1,"version":1}', body([dict(path='/', is_dir=1)]),
                body([dict(path='/a', is_dir=False, repo_id='foreign')])]:
        with pytest.raises(ValueError): request_body(raw)
