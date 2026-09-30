"""Protocol failures must discard whole pages, including completed partitions."""
import json
from copy import deepcopy
from unittest.mock import Mock

import pytest

from cloudfile_ext.search.access import SearchAccess
from cloudfile_ext.search.bounded import SearchFailure
from cloudfile_ext.search.native_many import NativePermissionMany, MAX_BYTES
from .test_search_access import snapshot, rule
from .test_bounded_search import REPO


def envelope(raw, permission=lambda path: 'rw'):
    request = json.loads(raw)
    return json.dumps(dict(version=1, repo_id=request['repo_id'], user=request['user'],
        items=[dict(path=p, permission=permission(p)) for p in request['paths']]))


def test_duplicates_root_and_normalization_keep_positional_contract():
    rpc = Mock(side_effect=envelope)
    hook = Mock(side_effect=lambda user, repo, path, native: native)
    adapter = NativePermissionMany(REPO, 'alice', rpc, hook)
    assert adapter(['/', '/a/', '/b', '/a']) == ['rw'] * 4
    assert json.loads(rpc.call_args.args[0])['paths'] == ['/', '/a', '/b', '/a']
    assert hook.call_count == 4


@pytest.mark.parametrize('path', ['', 'relative', '//bad', '/a//b', '/a/../b', '/./a', '/a\x00b', '/' + '中' * 1366, '/' + 'a/' * 130])
def test_bad_paths_fail_before_transport(path):
    rpc = Mock()
    with pytest.raises(SearchFailure): NativePermissionMany(REPO, 'alice', rpc, Mock())([path])
    rpc.assert_not_called()


def test_count_and_utf8_wire_budget_partition_independently():
    rpc = Mock(side_effect=envelope)
    adapter = NativePermissionMany(REPO, 'alice', rpc, lambda *args: args[-1])
    paths = ['/' + '中' * 1200 + str(i) for i in range(100)]
    assert adapter(paths) == ['rw'] * 100
    assert rpc.call_count > 2
    for call in rpc.call_args_list:
        assert len(call.args[0].encode()) <= MAX_BYTES
        assert len(json.loads(call.args[0])['paths']) <= 50


@pytest.mark.parametrize('change', ['missing', 'extra', 'duplicate', 'reordered', 'malformed', 'identity', 'repo', 'version', 'type', 'duplicate_key', 'null'])
def test_invalid_responses_fail_closed(change):
    def rpc(raw):
        value = json.loads(envelope(raw))
        if change == 'missing': value['items'].pop()
        elif change == 'extra': value['items'].append(value['items'][0])
        elif change == 'duplicate': value['items'][1] = value['items'][0]
        elif change == 'reordered': value['items'].reverse()
        elif change == 'malformed': value['items'][0]['permission'] = 'allow'
        elif change == 'identity': value['user'] = 'bob'
        elif change == 'repo': value['repo_id'] = 'other'
        elif change == 'version': value['version'] = True
        elif change == 'type': value['items'] = {}
        elif change == 'duplicate_key': return '{"version":1,"version":1}'
        elif change == 'null': return None
        return json.dumps(value)
    hook = Mock()
    with pytest.raises(SearchFailure): NativePermissionMany(REPO, 'alice', rpc, hook)(['/a', '/b'])
    hook.assert_not_called()


@pytest.mark.parametrize('failure', [RuntimeError(), TimeoutError()])
def test_partial_partition_provider_failure_discards_all(failure):
    calls = []
    def rpc(raw):
        calls.append(raw)
        if len(calls) == 2: raise failure
        return envelope(raw)
    with pytest.raises(SearchFailure):
        NativePermissionMany(REPO, 'alice', rpc, lambda *args: args[-1])(['/' + str(i) for i in range(51)])
    assert len(calls) == 2


def test_elapsed_timeout_discards_even_valid_reply():
    now = [0]
    def rpc(raw):
        now[0] = 10
        return envelope(raw)
    with pytest.raises(SearchFailure):
        NativePermissionMany(REPO, 'alice', rpc, lambda *args: args[-1], clock=lambda: now[0])(['/'])


def test_distinct_repo_and_identity_never_share_batches():
    rpc = Mock(side_effect=envelope)
    repos = [REPO, '22222222-2222-4222-8222-222222222222']
    for repo, user in zip(repos, ['alice', 'bob']):
        assert NativePermissionMany(repo, user, rpc, lambda *args: args[-1])(['/a']) == ['rw']
    assert [(json.loads(c.args[0])['repo_id'], json.loads(c.args[0])['user']) for c in rpc.call_args_list] == list(zip(repos, ['alice', 'bob']))


@pytest.mark.parametrize('mode', ['allow', 'deny', 'file', 'hidden', 'folder', 'mixed', 'hook'])
def test_scalar_and_multi_search_decisions_match(mode):
    state = snapshot()
    if mode == 'file': state['rules'] = [rule('/a/file', 'none', inherit=False)]
    if mode == 'hidden': state['rules'] = [rule('/a', 'invisible'), rule('/a/open', 'rw')]
    if mode == 'folder': state['native_rules'] = [rule('/a', 'invisible')]
    def scalar(path):
        return None if mode == 'deny' or mode == 'mixed' and path == '/b/file' else 'rw'
    def hook(user, repo, path, native):
        return None if mode == 'hook' and path == '/a/file' else native
    batch = NativePermissionMany(REPO, 'alice', lambda raw: envelope(raw, scalar), hook)
    old = SearchAccess(lambda: deepcopy(state), lambda p: hook('alice', REPO, p, scalar(p)) if scalar(p) else None)
    new = SearchAccess(lambda: deepcopy(state), None, native_many=batch)
    paths = ['/', '/a', '/a/file', '/a/open/file', '/b/file', '/a/file']
    new.prepare_many(paths)
    assert [old(p) for p in paths] == [new(p) for p in paths]
    old.assert_current()
    new.assert_current()


def test_second_pass_uses_fresh_engine_and_hooks():
    rpc = Mock(side_effect=envelope)
    hook = Mock(side_effect=lambda *args: args[-1])
    access = SearchAccess(snapshot, None, native_many=NativePermissionMany(REPO, 'alice', rpc, hook))
    assert access('/a/file')
    hook.side_effect = lambda *args: None
    with pytest.raises(SearchFailure): access.assert_current()
    assert rpc.call_count == 2
    assert hook.call_count == 4  # root and exact path evaluated again
