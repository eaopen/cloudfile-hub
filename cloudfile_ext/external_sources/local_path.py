# -*- coding: utf-8 -*-
"""The one source backend in this release: a directory in the container.

It covers **both** SMB and NFS, because the mount is the operator's job. They
mount the share on the host and bind-mount it into the container; from here it
is a directory, and one implementation serves both protocols with no new
dependency and no privileged container. docs/external-sources.md section three
has the full reasoning and states the cost: mounts are managed by ops, so an
administrator registers an already-mounted path rather than connecting to a
NAS from the web UI.

Not a stub. "The source is a directory" is a complete answer for the deployment
shape this targets, in the same sense that StaticDirectory is a complete
implementation of "the directory is the config file". A stub would be worse
than nothing here: an external source that lists as empty looks like a share
somebody forgot to populate, not like unimplemented code.

Symlinks are followed, but only within the root -- cloudfile_ext.external_
sources.paths re-resolves on every call, so a symlink added to the share after
registration cannot widen what is reachable. That check is why this module can
use plain os functions without auditing each one for escapes.
"""

import contextlib
import errno
import logging
import os

from cloudfile_ext.external_sources import paths
from cloudfile_ext.external_sources.providers import (
    Entry, Source, SourceError, SourceNotFound,
)

logger = logging.getLogger(__name__)

SOURCE_TYPE = 'local-path'


class LocalPathSource(Source):

    source_type = SOURCE_TYPE

    def __init__(self, allowed_roots=None):
        # Injectable so the tests can point the allow-list at a tmpdir. None
        # means "read CF_EXTERNAL_SOURCES_ROOTS at call time", not "allow
        # everything" -- see _roots().
        self._allowed_roots = allowed_roots

    def _roots(self):
        if self._allowed_roots is not None:
            return self._allowed_roots
        try:
            from django.conf import settings
        except ImportError:
            return paths.DEFAULT_ROOTS
        return getattr(settings, 'CF_EXTERNAL_SOURCES_ROOTS',
                       paths.DEFAULT_ROOTS) or paths.DEFAULT_ROOTS

    def _resolve(self, root_path, rel_path):
        return paths.resolve(root_path, rel_path, allowed_roots=self._roots())

    def list_dir(self, root_path, rel_path):
        abs_path = self._resolve(root_path, rel_path)
        try:
            with os.scandir(abs_path) as it:
                return [self._entry(e.name, e.path) for e in it]
        except NotADirectoryError:
            raise SourceNotFound('%s is not a directory' % rel_path)
        except FileNotFoundError:
            raise SourceNotFound('%s does not exist' % rel_path)
        except OSError as exc:
            raise self._os_error(exc, rel_path)

    def stat(self, root_path, rel_path):
        abs_path = self._resolve(root_path, rel_path)
        name = os.path.basename(abs_path.rstrip('/')) or '/'
        return self._entry(name, abs_path)

    @contextlib.contextmanager
    def open_file(self, root_path, rel_path):
        abs_path = self._resolve(root_path, rel_path)
        if os.path.isdir(abs_path):
            # Without this the open below succeeds on some platforms and the
            # first read fails mid-response, after headers are already sent.
            raise SourceNotFound('%s is a directory' % rel_path)
        try:
            handle = open(abs_path, 'rb')
        except FileNotFoundError:
            raise SourceNotFound('%s does not exist' % rel_path)
        except OSError as exc:
            raise self._os_error(exc, rel_path)
        try:
            yield handle
        finally:
            handle.close()

    def _entry(self, name, abs_path):
        try:
            st = os.stat(abs_path)
        except FileNotFoundError:
            # Reached through scandir on an entry that vanished, or through
            # stat() on a dangling symlink. Both mean "not there" from here.
            raise SourceNotFound('%s does not exist' % name)
        except OSError as exc:
            raise self._os_error(exc, name)
        return Entry(
            name=name,
            is_dir=os.path.isdir(abs_path),
            size=st.st_size,
            mtime=int(st.st_mtime),
        )

    def _os_error(self, exc, what):
        """Turn an OSError into the right SourceError subclass.

        A stale NFS handle or a dropped CIFS mount is an infrastructure fault,
        not a missing file, and must not surface as a 404 -- that reads as "the
        share is empty now" to anybody looking at the UI. Permission denied is
        deliberately in this branch too: it means the *container* cannot read
        the mount, which is an operator problem, and has nothing to do with the
        requesting user's authorisation.
        """
        logger.warning('external source %s failed on %r: %s',
                       self.source_type, what, exc)
        if exc.errno in (errno.ESTALE, errno.EIO, errno.ENOTCONN,
                         errno.EACCES, errno.EPERM, errno.EHOSTDOWN,
                         errno.ETIMEDOUT):
            return SourceError('source is unreachable or unreadable: %s' % exc)
        return SourceError('cannot read %s: %s' % (what, exc))


def register(registry):
    registry.register_external_source_provider(SOURCE_TYPE, LocalPathSource())
