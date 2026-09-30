"""Sparse-policy reuse must never replace current native read qualification."""
from copy import deepcopy
from unittest.mock import Mock

import pytest

from cloudfile_ext.search.access import SearchAccess
from cloudfile_ext.search.bounded import SearchFailure


def snapshot(rules=()):
    return dict(rules=list(rules), subjects=[('user', 'alice'), ('group', '7')],
        native_rules=[], native_subjects=[('user', 'alice'), ('group', '7')],
        native_paths=[], state=dict(permission='rw', status=0, active=True))


def rule(path, permission, subject_type='user', subject='alice', inherit=True):
    return dict(path=path, permission=permission, subject_type=subject_type,
        subject=subject, inherit=inherit)


@pytest.mark.parametrize('native', [None, 'none', 'invisible', 'preview', 'admin', True, 'r', 'rw'])
def test_only_explicit_native_read_permissions_can_search(native):
    access = SearchAccess(lambda: snapshot([rule('/', 'rw')]), lambda _: native)
    assert access('/a/file') is (native in ('r', 'rw'))


def test_personal_read_overrides_group_invisible_for_the_same_directory():
    access = SearchAccess(lambda: snapshot([rule('/a', 'invisible', 'group', '7'), rule('/a', 'r')]), lambda _: 'r')
    assert access('/a/file') is True
    access.assert_current()


def test_native_folder_invisible_is_checked_even_when_native_rpc_returns_read():
    value = snapshot()
    value['native_rules'] = [rule('/a', 'invisible', 'group', '7')]
    access = SearchAccess(lambda: value, lambda _: 'rw')
    assert access('/a/file') is False
    assert access('/ab/file') is True
    value['native_rules'].append(rule('/a', 'r'))
    assert SearchAccess(lambda: value, lambda _: 'rw')('/a/file') is True


def test_cf_grant_cannot_remove_a_native_folder_read_denial():
    value = snapshot([rule('/a', 'rw')])
    value['native_rules'] = [rule('/a', 'invisible', 'group', '7')]
    assert SearchAccess(lambda: value, lambda _: 'rw')('/a/file') is False


def test_same_priority_invisible_and_file_level_none_are_denied():
    access = SearchAccess(lambda: snapshot([rule('/a', 'r', 'group', '7'),
        rule('/a', 'invisible', 'group', '7')]), lambda _: 'rw')
    assert access('/a/file') is False
    access = SearchAccess(lambda: snapshot([rule('/a/file', 'none', inherit=False)]), lambda _: 'rw')
    assert access('/a') is True
    assert access('/a/file') is False
    assert access('/a/other') is True


def test_hidden_ancestor_is_not_exposed_by_a_deeper_grant():
    access = SearchAccess(lambda: snapshot([rule('/a', 'invisible'), rule('/a/b', 'r')]), lambda _: 'rw')
    assert access('/a/b/file') is False
    assert access('/ab/file') is True


def test_shared_ancestors_are_checked_once_and_results_rechecked_before_return():
    reader, native = Mock(return_value=snapshot()), Mock(return_value='rw')
    access = SearchAccess(reader, native)
    assert access('/a')
    for i in range(50):
        assert access('/a') and access('/a/file' + str(i))
    assert native.call_count == 52  # root, shared parent, fifty exact targets
    assert reader.call_count == 1
    access.assert_current()
    assert native.call_count == 104
    assert reader.call_count == 3


@pytest.mark.parametrize('change', ['rules', 'subjects', 'native_paths', 'state'])
def test_mutated_reader_state_rejects_results_and_changes_cursor_version(change):
    current = snapshot()
    access = SearchAccess(lambda: current, lambda _: 'rw')
    assert access('/a/file')
    if change == 'rules': current['rules'].append(rule('/a', 'invisible'))
    elif change == 'subjects': current['subjects'].remove(('group', '7'))
    elif change == 'native_paths': current['native_paths'].append('/a')
    else: current['state']['active'] = False
    assert SearchAccess(lambda: current, lambda _: 'rw').version != access.version
    with pytest.raises(SearchFailure): access.assert_current()


def test_native_revocation_during_search_rejects_cached_allow():
    native = Mock(return_value='r')
    access = SearchAccess(lambda: snapshot(), native)
    assert access('/a/file')
    native.return_value = None
    with pytest.raises(SearchFailure): access.assert_current()


def test_rule_order_does_not_change_the_permission_version():
    first = snapshot([rule('/a', 'r'), rule('/b', 'none')])
    second = deepcopy(first); second['rules'].reverse(); second['subjects'].reverse()
    assert SearchAccess(lambda: first, lambda _: 'r').version == SearchAccess(lambda: second, lambda _: 'r').version


def test_unknown_snapshot_and_native_failures_never_fall_open():
    with pytest.raises(SearchFailure): SearchAccess(Mock(side_effect=RuntimeError()), lambda _: 'rw')
    access = SearchAccess(lambda: snapshot(), Mock(side_effect=RuntimeError()))
    with pytest.raises(SearchFailure): access('/a/file')
    with pytest.raises(SearchFailure): SearchAccess(lambda: snapshot([rule('/a', 'invalid')]), lambda _: 'rw')


def test_budget_is_checked_even_for_cached_permissions():
    now = [0]
    access = SearchAccess(lambda: snapshot(), lambda _: 'r', clock=lambda: now[0])
    assert access('/a')
    now[0] = 10
    with pytest.raises(SearchFailure): access('/a')
