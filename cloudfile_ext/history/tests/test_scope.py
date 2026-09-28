# -*- coding: utf-8 -*-
"""Pure tests for the folder-history scope matcher (P2-10).

Contract: default scope = folder itself + direct children, never deeper;
current_folder_only = folder itself only (direct children excluded too).
"""

from cloudfile_ext.history.scope import touches_folder_paths

FOLDER = '/docs'


def pairs(*paths):
    """Turn bare paths into (old, new) rename-style pairs."""
    return [(p, None) for p in paths]


def test_folder_itself_hits_default():
    assert touches_folder_paths(pairs('/docs/'), FOLDER)


def test_direct_child_file_hits_default():
    assert touches_folder_paths(pairs('/docs/a.txt'), FOLDER)


def test_direct_child_dir_hits_default():
    assert touches_folder_paths(pairs('/docs/sub/'), FOLDER)


def test_deeper_level_excluded_by_default():
    assert not touches_folder_paths(pairs('/docs/sub/b.txt'), FOLDER)


def test_unrelated_path_excluded():
    assert not touches_folder_paths(pairs('/other/x.txt'), FOLDER)


def test_current_folder_only_keeps_folder_itself():
    assert touches_folder_paths(pairs('/docs/'), FOLDER, current_folder_only=True)


def test_current_folder_only_excludes_direct_children():
    assert not touches_folder_paths(pairs('/docs/a.txt'), FOLDER,
                                    current_folder_only=True)
    assert not touches_folder_paths(pairs('/docs/sub/'), FOLDER,
                                    current_folder_only=True)


def test_current_folder_only_excludes_deeper_levels():
    assert not touches_folder_paths(pairs('/docs/sub/b.txt'), FOLDER,
                                    current_folder_only=True)


def test_rename_into_scope_hits_via_new_name():
    assert touches_folder_paths([('/tmp/x.txt', '/docs/x.txt')], FOLDER)


def test_rename_out_of_scope_hits_via_old_name():
    assert touches_folder_paths([('/docs/x.txt', '/tmp/x.txt')], FOLDER)


def test_rename_deeper_excluded():
    assert not touches_folder_paths([('/tmp/x.txt', '/docs/sub/x.txt')], FOLDER)


def test_folder_scope_prefix_not_confused():
    # /docsx must not match /docs
    assert not touches_folder_paths(pairs('/docsx/a.txt'), FOLDER)


def test_root_folder_scope_is_noop():
    assert not touches_folder_paths(pairs('/a.txt'), '/')
