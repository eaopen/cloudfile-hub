# -*- coding: utf-8 -*-
"""The local-path backend against a real directory tree.

Two things are being protected here.

**Containment holds through the backend, not just in paths.py.** The download
endpoint calls open_file directly, so a backend that resolved paths itself --
or forgot to resolve at all -- would bypass the boundary while paths.py's own
tests stayed green.

**"Unreachable" never reads as "empty".** A dropped CIFS mount and an empty
share are indistinguishable to a caller, and only one of them is a fact about
the data. Anything that could return an empty list without having read the
share has to raise instead.

Django-free: the allow-list is injected, so _roots() never reaches for
django.conf.
"""

import errno
import os

import pytest

from cloudfile_ext.external_sources import paths
from cloudfile_ext.external_sources.local_path import (
    SOURCE_TYPE, LocalPathSource,
)
from cloudfile_ext.external_sources.providers import (
    SourceError, SourceNotFound,
)


@pytest.fixture
def share(tmp_path):
    root = tmp_path / 'shared' / 'external' / 'finance'
    os.makedirs(str(root / 'reports'))
    (root / 'reports' / 'q4.txt').write_text('numbers')
    (root / 'readme.md').write_text('# hi')
    outside = tmp_path / 'outside'
    os.makedirs(str(outside))
    (outside / 'passwd').write_text('root:x:0:0')
    os.symlink(str(outside), str(root / 'escape'))

    backend = LocalPathSource(
        allowed_roots=[str(tmp_path / 'shared' / 'external')])
    return backend, str(root), str(outside)


def test_source_type_is_registered_name():
    assert LocalPathSource().source_type == SOURCE_TYPE == 'local-path'


def test_list_dir_root(share):
    backend, root, _ = share
    names = {e.name for e in backend.list_dir(root, '/')}
    # 'escape' is listed: it is a symlink *inside* the root, and hiding it
    # would be cosmetic -- what matters is that reading through it fails.
    assert {'reports', 'readme.md'} <= names


def test_list_dir_reports_kind_and_size(share):
    backend, root, _ = share
    entries = {e.name: e for e in backend.list_dir(root, '/')}
    assert entries['reports'].is_dir is True
    assert entries['readme.md'].is_dir is False
    assert entries['readme.md'].size == len('# hi')
    assert entries['readme.md'].mtime > 0


def test_list_dir_subdirectory(share):
    backend, root, _ = share
    assert [e.name for e in backend.list_dir(root, '/reports')] == ['q4.txt']


def test_list_dir_missing_raises_not_found(share):
    backend, root, _ = share
    with pytest.raises(SourceNotFound):
        backend.list_dir(root, '/nope')


def test_list_dir_on_a_file_raises_not_found(share):
    backend, root, _ = share
    with pytest.raises(SourceNotFound):
        backend.list_dir(root, '/readme.md')


def test_traversal_is_refused(share):
    backend, root, _ = share
    with pytest.raises(paths.UnsafePath):
        backend.list_dir(root, '/../../outside')


def test_symlink_escape_is_refused_on_every_operation(share):
    """The escape must be blocked by the backend, on all three entry points.

    open_file is the one that matters most: it is reached straight from the
    download view, so a gap here reads arbitrary container files out to a user.
    """
    backend, root, _ = share
    with pytest.raises(paths.UnsafePath):
        backend.list_dir(root, '/escape')
    with pytest.raises(paths.UnsafePath):
        backend.stat(root, '/escape/passwd')
    with pytest.raises(paths.UnsafePath):
        with backend.open_file(root, '/escape/passwd'):
            pass


def test_root_outside_allow_list_is_refused(share):
    """A root the operator never allowed, even if it exists and is readable."""
    backend, _, outside = share
    with pytest.raises(paths.UnsafePath):
        backend.list_dir(outside, '/')


def test_open_file_reads_content(share):
    backend, root, _ = share
    with backend.open_file(root, '/reports/q4.txt') as handle:
        assert handle.read() == b'numbers'


def test_open_file_closes_the_handle(share):
    backend, root, _ = share
    with backend.open_file(root, '/readme.md') as handle:
        pass
    assert handle.closed


def test_open_file_on_a_directory_raises_before_streaming(share):
    """Caught up front, not by the first read.

    Opening a directory succeeds on some platforms, so without this check the
    failure lands mid-response -- after headers are already on the wire, where
    it becomes a truncated download rather than an error.
    """
    backend, root, _ = share
    with pytest.raises(SourceNotFound):
        with backend.open_file(root, '/reports'):
            pass


def test_open_missing_file_raises_not_found(share):
    backend, root, _ = share
    with pytest.raises(SourceNotFound):
        with backend.open_file(root, '/reports/nope.txt'):
            pass


def test_dangling_symlink_inside_root_is_not_found(share):
    backend, root, _ = share
    os.symlink(os.path.join(root, 'gone.txt'), os.path.join(root, 'dangling'))
    with pytest.raises(SourceNotFound):
        backend.stat(root, '/dangling')


@pytest.mark.parametrize('err', [errno.ESTALE, errno.EIO, errno.ENOTCONN,
                                 errno.EACCES, errno.ETIMEDOUT])
def test_unreachable_mount_raises_source_error_not_not_found(share, monkeypatch,
                                                             err):
    """A broken mount must not surface as 404, and must never list as empty.

    SourceNotFound would render as "this share no longer has anything in it",
    and returning [] would render as "the share is empty" -- both of which read
    as facts about the data. EACCES is in here on purpose: it means the
    *container* cannot read the mount, an operator fault unrelated to whether
    the requesting user was authorised.
    """
    backend, root, _ = share

    def boom(*args, **kwargs):
        raise OSError(err, os.strerror(err))

    monkeypatch.setattr(os, 'scandir', boom)
    with pytest.raises(SourceError) as caught:
        backend.list_dir(root, '/')
    assert not isinstance(caught.value, SourceNotFound)


def test_roots_default_when_nothing_is_injected():
    """No allow-list and no Django still means the restrictive default.

    Never "allow everything": that is the reading which turns a missing setting
    into an admin API that can register '/'.
    """
    assert LocalPathSource()._roots() == paths.DEFAULT_ROOTS
