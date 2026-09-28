# -*- coding: utf-8 -*-

from cloudfile_ext.favorites.identity import (
    pick_obj_id,
    relocate_path,
    should_backfill,
)


def test_pick_obj_id_prefers_file_id():
    assert pick_obj_id('f123', 'd123') == 'f123'
    assert pick_obj_id(None, 'd123') == 'd123'
    assert pick_obj_id('f123', None) == 'f123'
    assert pick_obj_id(None, None) is None
    assert pick_obj_id('', '') is None


def test_should_backfill_is_additive_and_lossless():
    assert should_backfill(None, 'obj1') is True
    assert should_backfill('', 'obj1') is True
    assert should_backfill('obj0', 'obj1') is False   # already keyed: keep
    assert should_backfill(None, None) is False       # unresolved: leave, never delete
    assert should_backfill(None, '') is False


def test_relocate_path_moves_the_directory_itself():
    assert relocate_path('/a/b', '/a/b/', '/c/d/') == '/c/d'


def test_relocate_path_rewrites_descendants_only():
    assert relocate_path('/a/b/c.txt', '/a/b/', '/c/d/') == '/c/d/c.txt'
    assert relocate_path('/a/b/x/y.md', '/a/b/', '/c/d/') == '/c/d/x/y.md'


def test_relocate_path_does_not_match_sibling_prefix():
    # '/a/bc.txt' must not be treated as under '/a/b/'
    assert relocate_path('/a/bc.txt', '/a/b/', '/c/d/') is None
    assert relocate_path('/a/b', '/a/bc/', '/c/d/') is None


def test_relocate_path_leaves_unrelated_paths_alone():
    assert relocate_path('/other/f.txt', '/a/b/', '/c/d/') is None
