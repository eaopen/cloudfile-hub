# -*- coding: utf-8 -*-
"""ACL rules follow their object when it is renamed or moved.

Django-free: the tick takes an injected state model, activity source and
migrator, so the same file runs under the shared pytest-only checks.
"""

import pytest

from cloudfile_ext.acl import migration


# -- rewrite_path / plan_migration (the policy) ------------------------------

def test_exact_path_follows_a_rename():
    assert migration.rewrite_path('/docs/old.xlsx', '/docs/old.xlsx',
                                 '/docs/new.xlsx') == '/docs/new.xlsx'


def test_descendant_rules_follow_a_folder_move():
    assert migration.rewrite_path('/docs/a/b.txt', '/docs', '/资料/文档') == \
        '/资料/文档/a/b.txt'


def test_unrelated_path_is_left_alone():
    assert migration.rewrite_path('/other/x.txt', '/docs', '/资料') is None


def test_sibling_with_shared_prefix_is_not_matched():
    # '/docs2' must not be treated as a descendant of '/docs'.
    assert migration.rewrite_path('/docs2/x.txt', '/docs', '/资料') is None


def test_moving_to_library_root_flattens_the_suffix():
    assert migration.rewrite_path('/docs/a.txt', '/docs', '/') == '/a.txt'


def test_plan_reports_only_changed_paths():
    plan = migration.plan_migration(
        ['/docs', '/docs/a.txt', '/docs2/x', '/other'], '/docs', '/资料')
    assert plan == [('/docs', '/资料'), ('/docs/a.txt', '/资料/a.txt')]


# -- moved_entries (activity parsing) ---------------------------------------

def test_single_op_row_uses_detail_old_path():
    event = {'op_type': 'rename', 'repo_id': 'r1', 'path': '/docs/new',
             'detail': {'old_path': '/docs/old'}}
    assert migration.moved_entries(event) == [('r1', '/docs/old', '/docs/new')]


def test_batch_row_expands_items():
    event = {'op_type': 'batch_move', 'repo_id': 'r1', 'path': None,
             'detail': [{'path': '/b', 'old_path': '/a'},
                        {'path': '/d', 'old_path': '/c'}]}
    assert migration.moved_entries(event) == [
        ('r1', '/a', '/b'), ('r1', '/c', '/d')]


def test_non_moving_op_is_ignored():
    event = {'op_type': 'edit', 'repo_id': 'r1', 'path': '/a',
             'detail': {'old_path': '/b'}}
    assert migration.moved_entries(event) == []


def test_move_without_old_path_is_ignored():
    assert migration.moved_entries(
        {'op_type': 'move', 'repo_id': 'r1', 'path': '/a', 'detail': {}}) == []


# -- migration_tick (watermark behaviour) ------------------------------------

class FakeState(object):
    def __init__(self, cursor=0):
        self.cursor = cursor
        self.advanced = []

    def get_cursor(self, name):
        return self.cursor

    def advance(self, name, last_id, status, detail=''):
        self.advanced.append((last_id, status, detail))
        self.cursor = last_id


class FakeStateModel(object):
    def __init__(self, cursor=0):
        self.objects = FakeState(cursor)


def test_tick_migrates_and_advances_watermark():
    state = FakeStateModel()
    calls = []

    def activities_since(cursor, limit):
        assert cursor == 0
        return [
            {'id': 5, 'op_type': 'rename', 'repo_id': 'r1', 'path': '/new',
             'detail': {'old_path': '/old'}},
            {'id': 6, 'op_type': 'edit', 'repo_id': 'r1', 'path': '/x',
             'detail': {}},
        ]

    changed = migration.migration_tick(
        state_model=state, activities_since=activities_since,
        migrate=lambda repo, old, new: calls.append((repo, old, new)) or 2)

    assert changed == 2
    assert calls == [('r1', '/old', '/new')]
    # Watermark moves past the whole batch, including the ignored row.
    assert state.objects.advanced[-1][0] == 6
    assert state.objects.advanced[-1][1] == 'ok'


def test_tick_is_a_noop_without_activity():
    state = FakeStateModel(cursor=42)
    assert migration.migration_tick(
        state_model=state, activities_since=lambda cursor, limit: [],
        migrate=lambda *a: 1) == 0
    assert state.objects.advanced == []


def test_failed_migration_keeps_the_watermark_and_marks_error():
    state = FakeStateModel()

    def boom(repo, old, new):
        raise RuntimeError('db down')

    migration.migration_tick(
        state_model=state,
        activities_since=lambda cursor, limit: [
            {'id': 9, 'op_type': 'move', 'repo_id': 'r1', 'path': '/b',
             'detail': {'old_path': '/a'}}],
        migrate=boom)

    # Not advanced to the failing row's id: the next tick retries it.
    assert state.objects.advanced[-1][0] == 0
    assert state.objects.advanced[-1][1] == 'error'
