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
It never grants access without a native qualification: an absent or denied
native verdict is refused by ``resolve()``/``narrow_to_native()`` before this
hook returns anything stronger.

Failure policy: a runtime error must not silently drop a stored deny, but it
also must not take the whole entry point down — Seahub has no 503 mapping for
this seam (today it enforces no ACL at all here). The hook therefore keeps the
native verdict on error and logs loudly; an ACL outage degrades to the CE
behaviour instead of a false 403 for every user.

Scope note: the seam carries only a path, not an object kind. The decision is
therefore evaluated as a directory, which covers the directory rules and the
directory-level denies that Seahub's write paths depend on; file-kind rows are
not the input of this check.
"""
import logging

logger = logging.getLogger(__name__)

# Permissions this hook is allowed to reinterpret. ``admin`` is a management
# marker with owner-level bypass and custom permissions are Pro-specific; both
# are returned untouched rather than flattened into r/rw.
_NATIVE_CONTENT_PERMISSIONS = ('r', 'rw')


def _authority(username):
    from .acl_runtime import Authority
    return Authority(username)


def check_permission(username, repo_id, path, permission):
    """Return the effective permission for ``path``, or None to deny."""
    if permission not in _NATIVE_CONTENT_PERMISSIONS:
        return permission
    try:
        decision = _authority(username).effective(repo_id, path, 'dir')
    except Exception:
        logger.exception(
            'CloudFile ACL unavailable; keeping the native verdict '
            '(user=%s repo=%s path=%s permission=%s)', username, repo_id, path, permission)
        return permission
    if not decision.can_read:
        return None
    # 'rw' here may exceed the native verdict on purpose: a directory rule that
    # matched this qualified subject raised it, which is the documented
    # behaviour. An ACL 'r' still narrows a native 'rw'.
    return decision.permission
