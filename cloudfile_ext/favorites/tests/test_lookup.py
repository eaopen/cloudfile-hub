"""Wide/deep/failing trees share actual lookup budgets, not only depth guards."""
import stat
from types import SimpleNamespace
from unittest.mock import Mock

from cloudfile_ext.favorites.lookup import LookupBudget, lookup_content_hint


def entry(name, obj='other', directory=False):
    return SimpleNamespace(obj_name=name, obj_id=obj,
                           mode=stat.S_IFDIR if directory else stat.S_IFREG)


def test_same_content_at_two_paths_is_ambiguous():
    result = lookup_content_hint(lambda *_: [entry('a', 'shared'), entry('b', 'shared')], 'repo', 'shared')
    assert result.status == 'ambiguous' and result.path is None


def test_unique_hit_is_only_a_hint_and_must_finish_the_scan():
    calls = Mock(side_effect=[[entry('a', 'shared'), entry('sub', directory=True)], []])
    result = lookup_content_hint(calls, 'repo', 'shared')
    assert result.status == 'unique' and result.path == '/a'
    assert calls.call_count == 2


def test_node_budget_bounds_wide_directory_and_cannot_assert_uniqueness():
    calls = Mock(return_value=[entry(str(i), 'shared' if i == 0 else 'other') for i in range(100)])
    budget = LookupBudget(max_entries=5)
    result = lookup_content_hint(calls, 'repo', 'shared', budget=budget)
    assert result.status == 'budget_exhausted' and result.path is None
    assert budget.entries == 0 and calls.call_count == 1


def test_rpc_budget_bounds_many_empty_directories():
    calls = Mock(side_effect=lambda repo, path: [entry(str(i), directory=True) for i in range(20)] if path == '/' else [])
    result = lookup_content_hint(calls, 'repo', 'shared', budget=LookupBudget(max_calls=3))
    assert result.status == 'budget_exhausted' and calls.call_count == 3


def test_shared_budget_cannot_be_reset_for_each_favorite():
    calls = Mock(return_value=[])
    budget = LookupBudget(max_calls=1)
    assert lookup_content_hint(calls, 'repo', 'first', budget=budget).status == 'not_found'
    assert lookup_content_hint(calls, 'repo', 'second', budget=budget).status == 'budget_exhausted'
    assert calls.call_count == 1


def test_time_budget_and_service_errors_are_not_not_found():
    now = [0.0]
    budget = LookupBudget(max_seconds=0.1, clock=lambda: now[0])
    def slow(*_):
        now[0] = 0.2
        return []
    assert lookup_content_hint(slow, 'repo', 'id', budget=budget).status == 'budget_exhausted'
    unavailable = Mock(side_effect=RuntimeError('rpc unavailable'))
    assert lookup_content_hint(unavailable, 'repo', 'id').status == 'unavailable'


def test_depth_budget_bounds_a_deep_tree_without_python_recursion():
    calls = Mock(return_value=[entry('sub', directory=True)])
    assert lookup_content_hint(calls, 'repo', 'id', max_depth=2).status == 'budget_exhausted'
    assert calls.call_count == 2
