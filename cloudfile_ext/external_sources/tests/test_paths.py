# -*- coding: utf-8 -*-
"""Path containment -- the whole security boundary of this capability.

The invariant: **no request can ever cause a read outside the resolved root**,
and the root itself can never be outside the configured allow-list.

Two escapes with different shapes are covered, because one check cannot catch
both. Lexical traversal (``..`` in the request) is caught without touching the
filesystem. Symlink escape is not lexical at all -- the request path can be
entirely innocent -- so it needs realpath plus a segment-wise prefix compare.

Django-free, like the rest of cloudfile_ext's tests: the shared checks
(cloudfile-docker/tools/run-checks.sh) install pytest and nothing else, so a
test that needed Django would be silently skipped in CI and read as coverage
while providing none.

Real symlinks on a real tmpdir rather than a mocked realpath: the bug this
guards against lives in the interaction between normalisation and resolution,
and a stubbed resolver is exactly where that interaction is assumed away.
"""

import os

import pytest

from cloudfile_ext.external_sources import paths


# -- lexical normalisation --------------------------------------------------

@pytest.mark.parametrize('given,expected', [
    (None, '/'),
    ('', '/'),
    ('/', '/'),
    ('a', '/a'),
    ('/a/b', '/a/b'),
    ('//a///b//', '/a/b'),
    ('/a/./b', '/a/b'),
    ('/a b/c-d_e.txt', '/a b/c-d_e.txt'),
])
def test_normalize_rel_path(given, expected):
    assert paths.normalize_rel_path(given) == expected


@pytest.mark.parametrize('given', [
    '..', '/..', '/a/../b', '/a/..', 'a/../../etc/passwd', '/../etc/passwd',
])
def test_normalize_rel_path_refuses_traversal(given):
    with pytest.raises(paths.UnsafePath):
        paths.normalize_rel_path(given)


def test_normalize_rel_path_refuses_null_byte():
    # A null truncates the name at the C boundary, so what gets opened is not
    # what was validated.
    with pytest.raises(paths.UnsafePath):
        paths.normalize_rel_path('/a\0b')


def test_normalize_rel_path_refuses_non_string():
    with pytest.raises(paths.UnsafePath):
        paths.normalize_rel_path(42)


def test_backslash_is_a_separator_not_a_traversal_hole():
    """Backslash splits, so a Windows-style path cannot smuggle a segment.

    It is a legal filename character on POSIX, so treating it as a separator
    means a genuine file named ``a\\b`` becomes unreachable -- the safe
    direction. What must not happen is ``..\\..`` slipping past the '..' check
    because the segment was never split.
    """
    assert paths.normalize_rel_path('a\\b') == '/a/b'
    with pytest.raises(paths.UnsafePath):
        paths.normalize_rel_path('a\\..\\..\\etc')


# -- root allow-list -------------------------------------------------------

def test_root_must_be_under_an_allowed_prefix(tmp_path):
    allowed = [str(tmp_path / 'ok')]
    os.makedirs(str(tmp_path / 'ok' / 'share'))
    os.makedirs(str(tmp_path / 'elsewhere'))

    assert paths.check_root_allowed(str(tmp_path / 'ok' / 'share'), allowed)
    with pytest.raises(paths.UnsafePath):
        paths.check_root_allowed(str(tmp_path / 'elsewhere'), allowed)


def test_sibling_prefix_is_not_inside(tmp_path):
    """``/shared/external-evil`` is not under ``/shared/external``.

    A str.startswith comparison accepts it. The compare is segment-wise for
    exactly this case, and a plausible "simplification" of _is_within would
    reintroduce it.
    """
    allowed = [str(tmp_path / 'external')]
    os.makedirs(str(tmp_path / 'external'))
    os.makedirs(str(tmp_path / 'external-evil'))

    with pytest.raises(paths.UnsafePath):
        paths.check_root_allowed(str(tmp_path / 'external-evil'), allowed)


def test_root_that_symlinks_out_is_refused(tmp_path):
    """A root inside the allow-list whose realpath is outside it.

    Checking only the declared path passes this: ``<allowed>/nas`` looks fine.
    Every later containment check would then be measured against ``/``, so
    every traversal would succeed -- one missing check silently disables all of
    them.
    """
    allowed = [str(tmp_path / 'ok')]
    os.makedirs(str(tmp_path / 'ok'))
    os.makedirs(str(tmp_path / 'secret'))
    os.symlink(str(tmp_path / 'secret'), str(tmp_path / 'ok' / 'nas'))

    with pytest.raises(paths.UnsafePath):
        paths.check_root_allowed(str(tmp_path / 'ok' / 'nas'), allowed)


def test_empty_allow_list_refuses_everything(tmp_path):
    """An empty list denies, it does not mean "unrestricted".

    The inverted reading is the one that turns a misconfiguration into "/ is an
    external source", so it gets its own test rather than relying on the
    default value being present.
    """
    with pytest.raises(paths.UnsafePath):
        paths.check_root_allowed(str(tmp_path), [])


@pytest.mark.parametrize('given', ['', None, 'relative/path', '/a\0b'])
def test_normalize_root_refuses_unusable(given):
    with pytest.raises(paths.UnsafePath):
        paths.normalize_root(given)


def test_default_roots_are_not_the_filesystem_root():
    """The shipped default must not be '/' or empty.

    This is the one property that makes the capability safe out of the box
    rather than safe-if-configured.
    """
    assert paths.DEFAULT_ROOTS
    for root in paths.DEFAULT_ROOTS:
        assert root not in ('', '/')
        assert root.startswith('/')


# -- resolution ------------------------------------------------------------

@pytest.fixture
def share(tmp_path):
    """An allowed root containing a file, a subdir and an escaping symlink."""
    root = tmp_path / 'shared' / 'external' / 'finance'
    os.makedirs(str(root / 'sub'))
    (root / 'sub' / 'q4.txt').write_text('numbers')
    outside = tmp_path / 'outside'
    os.makedirs(str(outside))
    (outside / 'passwd').write_text('root:x:0:0')
    os.symlink(str(outside), str(root / 'escape'))
    os.symlink(str(outside / 'passwd'), str(root / 'escape.txt'))
    return {
        'root': str(root),
        'allowed': [str(tmp_path / 'shared' / 'external')],
        'outside': str(outside),
    }


def test_resolve_root_and_children(share):
    assert paths.resolve(share['root'], '/', share['allowed']) == \
        os.path.realpath(share['root'])
    assert paths.resolve(share['root'], '/sub/q4.txt', share['allowed']) == \
        os.path.realpath(os.path.join(share['root'], 'sub', 'q4.txt'))


def test_resolve_refuses_symlinked_directory_escape(share):
    """The request path is innocent; only realpath reveals the escape.

    This is the case that makes re-checking on every access necessary: the
    symlink can appear on the share long after the source was registered, put
    there by any user of the NAS.
    """
    with pytest.raises(paths.UnsafePath):
        paths.resolve(share['root'], '/escape/passwd', share['allowed'])


def test_resolve_refuses_symlinked_file_escape(share):
    with pytest.raises(paths.UnsafePath):
        paths.resolve(share['root'], '/escape.txt', share['allowed'])


def test_resolve_refuses_traversal(share):
    with pytest.raises(paths.UnsafePath):
        paths.resolve(share['root'], '/sub/../../outside/passwd',
                      share['allowed'])


def test_resolve_allows_nonexistent_path(share):
    """Resolution is not an existence check.

    Callers that must tell "not there" from "not allowed" stat afterwards; if
    this raised UnsafePath for a missing file, that distinction would be lost
    and every 404 would look like an attempted escape.
    """
    result = paths.resolve(share['root'], '/sub/nope.txt', share['allowed'])
    assert result.endswith('/sub/nope.txt')
