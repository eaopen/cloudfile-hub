# -*- coding: utf-8 -*-
"""Seahub permission seam: the V2 directory decision for native folder checks.

``seahub.views.check_folder_permission`` runs the native CE verdict first and
then hands it to ``cloudfile_ext.hooks.check_permission``. Without a hook the
ACL is never consulted on the write paths Seahub owns (``upload-link``,
``dir`` mutations, ...), so a directory rule can never take effect there even
though the fileserver already enforces the same rules.

This hook applies the one decision produced by :class:`Authority`, which
evaluates the stored rules on top of the native grant. A library read may be
raised to write by a matching rule — the native grant is the qualification,
not the ceiling (see ``docs/v2.0/directory-inheritance-deny-ce-pro-20261016.md``).
A positive shared directory can qualify a user without library membership.
Every content verdict, including native owner/admin, goes through Authority.

Failure policy: refusals return None; authority failures raise a distinct
exception so the native request seam can mark the response as unavailable.

Scope note: the seam carries only a path, not an object kind. The decision is
therefore evaluated as a directory, which covers the directory rules and the
directory-level denies that Seahub's write paths depend on; file-kind rows are
not the input of this check.
"""
import logging

logger = logging.getLogger(__name__)


def _authority(username):
    from .acl_runtime import Authority
    return Authority(username)


def _canonical(path):
    """Collapse duplicate and trailing slashes; reject traversal.

    Seahub hands this seam paths like ``/dir/`` -- canonical_path() rejects a
    trailing slash, which used to abort the whole adjudication and fall back to
    the native verdict. Normalising here keeps one contract for every caller.
    """
    segments = [seg for seg in (path or '').split('/') if seg not in ('', '.')]
    if any(seg == '..' for seg in segments):
        raise ValueError('invalid path')
    return '/' + '/'.join(segments)


def check_permission(username, repo_id, path, permission):
    """Return the effective permission for ``path``, or None to deny."""
    try:
        decision = _authority(username).effective(repo_id, _canonical(path), 'dir')
    except PermissionError:
        return None
    except Exception as error:
        logger.exception(
            'CloudFile ACL unavailable; refusing native fallback '
            '(user=%s repo=%s path=%s permission=%s)', username, repo_id, path, permission)
        from .acl_runtime import ACLUnavailable
        raise ACLUnavailable('ACL unavailable') from error
    if not decision.can_read:
        return None
    # 'rw' here may exceed the native verdict on purpose: a directory rule that
    # matched this qualified subject raised it, which is the documented
    # behaviour. An ACL 'r' still narrows a native 'rw'.
    return decision.permission
