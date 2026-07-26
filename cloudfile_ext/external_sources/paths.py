# -*- coding: utf-8 -*-
"""Path containment for external sources.

This module is the whole security boundary of the capability, so it is kept
free of Django, the database and Seafile: it has to be runnable -- and
mutation-testable -- on its own. Everything here is about one question:

    given a registered root and a path that came from an HTTP request, which
    absolute path may be read, and is it still inside that root?

Two distinct escapes have to be stopped, and they need different checks:

* **Traversal in the request.** ``?p=/../../etc/passwd``. Purely lexical, so
  it is caught by rejecting ``..`` segments before touching the filesystem.

* **Symlinks on the share.** A file inside the root pointing at ``/etc``. This
  is *not* lexical -- the request path can be perfectly innocent -- so it needs
  ``realpath`` and a prefix comparison against the resolved root.

The second one is why containment is re-checked on every access rather than
once at registration. The root is a mount of somebody else's file server:
every user who can write to that share can add a symlink to it at any time
after it was registered. Validating only at registration hands the security of
this deployment to whoever has write access on the NAS.

Both checks are cheap next to the I/O that follows them, so there is no
fast-path that skips either.
"""

import os
import posixpath

#: Container paths a source root may live under, when nothing overrides it.
#: A *safe default* rather than a required setting: an empty allow-list would
#: mean the admin API could register / as an external source, and "secure only
#: if the operator configured it correctly" is not a property worth shipping.
DEFAULT_ROOTS = ('/shared/external',)


class UnsafePath(Exception):
    """A path escapes its root, or cannot be represented safely.

    One exception for both escape kinds on purpose. Callers turn this into a
    single 400/404 -- distinguishing "you tried to traverse" from "that is a
    symlink out of the tree" in a response body only tells a prober which of
    their attempts got further.
    """


def normalize_rel_path(path):
    """Normalise a request path to ``/`` or ``/a/b``, or raise UnsafePath.

    Lexical only -- no filesystem access, so this is safe to call on input
    before deciding whether a source even exists.
    """
    if path is None:
        path = '/'
    if not isinstance(path, str):
        raise UnsafePath('path must be a string')
    if '\0' in path:
        # Would truncate the name at the C boundary, so what gets opened is
        # not what was validated.
        raise UnsafePath('path contains a null byte')

    # Backslash is a separator on SMB shares and a legal filename character on
    # POSIX. Treating it as a separator here would let a genuine filename be
    # split into segments; leaving it alone means a Windows-style path simply
    # does not match anything, which is the safe direction.
    parts = []
    for segment in path.replace('\\', '/').split('/'):
        if segment in ('', '.'):
            continue
        if segment == '..':
            raise UnsafePath('path contains a .. segment')
        parts.append(segment)

    return '/' + '/'.join(parts)


def normalize_root(root_path):
    """Normalise a registered root to an absolute, slash-free-suffix path."""
    if not root_path or not isinstance(root_path, str):
        raise UnsafePath('root path must be a non-empty string')
    if '\0' in root_path:
        raise UnsafePath('root path contains a null byte')
    if not root_path.startswith('/'):
        raise UnsafePath('root path must be absolute')
    normalized = posixpath.normpath(root_path)
    if normalized != '/' and normalized.endswith('/'):
        normalized = normalized.rstrip('/')
    return normalized


def _is_within(child, parent):
    """Whether `child` is `parent` or below it, comparing whole segments.

    Segment-wise rather than ``str.startswith``, which would accept
    ``/shared/external-evil`` as being under ``/shared/external``.
    """
    if child == parent:
        return True
    return child.startswith(parent.rstrip('/') + '/')


def check_root_allowed(root_path, allowed_roots=None, realpath=os.path.realpath):
    """Return the resolved root, or raise UnsafePath.

    Both the declared and the resolved root must be inside the allow-list. The
    declared one alone is not enough: ``/shared/external/nas`` may itself be a
    symlink to ``/``, in which case every later containment check would be
    measured against ``/`` and pass.
    """
    normalized = normalize_root(root_path)
    roots = [normalize_root(r) for r in
             (DEFAULT_ROOTS if allowed_roots is None else allowed_roots)]
    if not roots:
        raise UnsafePath('no allowed root prefixes are configured')

    if not any(_is_within(normalized, r) for r in roots):
        raise UnsafePath('root path is not under an allowed prefix: %s'
                         % ', '.join(roots))

    resolved = normalize_root(realpath(normalized))
    if not any(_is_within(resolved, r) for r in roots):
        raise UnsafePath('root path resolves outside the allowed prefixes')

    return resolved


def resolve(root_path, rel_path, allowed_roots=None,
            realpath=os.path.realpath):
    """Absolute path to read for `rel_path` inside `root_path`.

    Raises UnsafePath unless the result is inside the resolved root *and* that
    root is inside the allow-list. Does not check existence -- a caller that
    needs to distinguish "not there" from "not allowed" stats afterwards, and
    one that does not can let the open fail.
    """
    resolved_root = check_root_allowed(root_path, allowed_roots, realpath)
    rel = normalize_rel_path(rel_path)

    if rel == '/':
        return resolved_root

    candidate = posixpath.join(resolved_root, rel.lstrip('/'))
    resolved = realpath(candidate)

    # normpath, not normalize_root: a resolved path is already absolute, and
    # normalize_root would reject nothing that realpath can return.
    resolved = posixpath.normpath(resolved)
    if not _is_within(resolved, resolved_root):
        raise UnsafePath('path escapes the source root')

    return resolved
