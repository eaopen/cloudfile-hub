# -*- coding: utf-8 -*-
"""Payload-shape contracts the shadow layer owes the native React library view.

Both helpers exist because the shadow answers payloads that upstream's own React
code reads. Getting them wrong does not fail loudly: the folder tree throws
inside a promise whose ``catch`` only clears a loading flag, so the symptom is a
tree that quietly stops following navigation. Hence unit tests here, next to the
container gate that exercises the same shapes end to end.
"""

import pytest

from cloudfile_ext.external_sources.service import ancestor_dirs, native_parent_dir


@pytest.mark.parametrize('path,expected', [
    ('/', '/'),
    ('', '/'),
    (None, '/'),
    ('/a', '/a/'),
    ('/a/b', '/a/b/'),
    ('/a/b/', '/a/b/'),            # already native-shaped: left unchanged
    ('/部门/共享', '/部门/共享/'),   # non-ASCII segments are not special
])
def test_native_parent_dir_matches_normalize_dir_path(path, expected):
    assert native_parent_dir(path) == expected


def test_native_parent_dir_agrees_with_upstream_helper():
    """The property that matters is equality with upstream's own format.

    ``seahub.utils.normalize_dir_path`` returns ``'/' + path.strip('/') + '/'``
    for anything non-empty, which is what the React side slices back off to get
    its folder-tree node key.
    """
    for raw in ['/a', '/a/b', '/a/b/c']:
        assert native_parent_dir(raw) == '/' + raw.strip('/') + '/'


@pytest.mark.parametrize('path,expected', [
    ('/', ['/']),
    ('', ['/']),
    ('/a', ['/', '/a']),
    ('/a/b', ['/', '/a', '/a/b']),
    ('/a/b/', ['/', '/a', '/a/b']),
])
def test_ancestor_dirs_is_ancestor_first(path, expected):
    assert ancestor_dirs(path) == expected


def test_ancestor_dirs_ends_with_the_requested_directory():
    """The requested directory must come last: the tree fills it last."""
    for path in ['/a', '/a/b', '/x/y/z']:
        assert ancestor_dirs(path)[-1] == path
