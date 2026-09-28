# -*- coding: utf-8 -*-
"""P2-06 precheck policy: pure, no Django.

The properties worth protecting here are the security-relevant ones: a source
the user cannot read/write is never copied/moved, a cross-space move is gated
on admin, a cyclic move is rejected, and a name conflict is never a silent
overwrite. Pure logic, no Django needed -- see test_providers for why that
matters.
"""

import pytest

from cloudfile_ext.fileops import policy


# -- permission matrix -----------------------------------------------------

def test_copy_needs_source_read_and_target_write():
    assert policy.check_permissions('copy', 'r', 'rw', False, False) is None
    assert policy.check_permissions('copy', 'rw', 'rw', False, False) is None
    assert policy.check_permissions('copy', 'admin', 'rw', False, False) is None


def test_copy_rejects_unreadable_source():
    assert policy.check_permissions('copy', 'none', 'rw', False, False) == \
        policy.REASON_PERMISSION


def test_copy_rejects_readonly_target():
    assert policy.check_permissions('copy', 'rw', 'r', False, False) == \
        policy.REASON_PERMISSION


def test_move_needs_source_write():
    assert policy.check_permissions('move', 'rw', 'rw', False, False) is None
    assert policy.check_permissions('move', 'r', 'rw', False, False) == \
        policy.REASON_PERMISSION


def test_move_rejects_readonly_target():
    assert policy.check_permissions('move', 'rw', 'r', False, False) == \
        policy.REASON_PERMISSION


def test_cross_owner_move_needs_source_admin():
    assert policy.check_permissions('move', 'rw', 'rw', True, False) == \
        policy.REASON_CROSS_SPACE
    assert policy.check_permissions('move', 'rw', 'rw', True, True) is None


def test_cross_owner_copy_is_not_escalated():
    # Copying into another space is governed by plain read/write; only *move*
    # removes content from somebody else's space.
    assert policy.check_permissions('copy', 'rw', 'rw', True, False) is None


# -- move cycle ------------------------------------------------------------

def test_move_cycle_into_own_subtree():
    assert policy.check_move_cycle('/a', 'b', '/a/b/c', 'r1', 'r1') is True


def test_move_cycle_same_location():
    assert policy.check_move_cycle('/a', 'b', '/a', 'r1', 'r1') is True


def test_move_cycle_into_self():
    assert policy.check_move_cycle('/a', 'b', '/a/b', 'r1', 'r1') is True


def test_move_cycle_not_cyclic():
    assert policy.check_move_cycle('/a', 'b', '/c', 'r1', 'r1') is False


def test_cross_repo_move_is_never_cyclic():
    assert policy.check_move_cycle('/a', 'b', '/a/b/c', 'r1', 'r2') is False


# -- limits ----------------------------------------------------------------

def test_size_limit_zero_means_unlimited():
    assert policy.check_single_file_size(10 ** 9, 0) is False


def test_size_limit_over():
    assert policy.check_single_file_size(11, 10) is True
    assert policy.check_single_file_size(10, 10) is False


def test_depth_limit():
    assert policy.check_folder_depth(6, 5) is True
    assert policy.check_folder_depth(5, 5) is False
    assert policy.check_folder_depth(100, 0) is False


def test_count_and_batch_limits():
    assert policy.check_item_count(101, 100) is True
    assert policy.check_batch_size(2 * 1024, 1024) is True
    assert policy.check_batch_size(1024, 0) is False


# -- name conflict ---------------------------------------------------------

def test_no_conflict_returns_unchanged():
    assert policy.resolve_conflict('f.txt', {'g.txt'}, policy.CONFLICT_RENAME) == 'f.txt'


def test_conflict_rename_keeps_both():
    assert policy.resolve_conflict('f.txt', {'f.txt'}, policy.CONFLICT_RENAME) == 'f (1).txt'
    assert policy.resolve_conflict('f.txt', {'f.txt', 'f (1).txt'},
                                   policy.CONFLICT_RENAME) == 'f (2).txt'


def test_conflict_rename_no_extension():
    assert policy.resolve_conflict('README', {'README'}, policy.CONFLICT_RENAME) == 'README (1)'


def test_conflict_skip_returns_none():
    assert policy.resolve_conflict('f.txt', {'f.txt'}, policy.CONFLICT_SKIP) is None


def test_conflict_overwrite_is_explicit_only():
    assert policy.resolve_conflict('f.txt', {'f.txt'}, policy.CONFLICT_OVERWRITE) == 'f.txt'
    # The default is rename, never overwrite.
    assert policy.DEFAULT_CONFLICT_POLICY == policy.CONFLICT_RENAME


# -- idempotency -----------------------------------------------------------

def test_idempotency_key_is_order_independent():
    a = policy.build_idempotency_key('u', 'copy', 'r1', '/src', ['b', 'a'],
                                     'r2', '/dst')
    b = policy.build_idempotency_key('u', 'copy', 'r1', '/src', ['a', 'b'],
                                     'r2', '/dst')
    assert a == b


def test_idempotency_key_distinguishes_intent():
    a = policy.build_idempotency_key('u', 'copy', 'r1', '/src', ['a'],
                                     'r2', '/dst')
    b = policy.build_idempotency_key('u', 'copy', 'r1', '/src', ['a'],
                                     'r2', '/other')
    assert a != b
    c = policy.build_idempotency_key('u2', 'copy', 'r1', '/src', ['a'],
                                     'r2', '/dst')
    assert a != c
