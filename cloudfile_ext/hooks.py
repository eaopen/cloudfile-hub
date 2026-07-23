# -*- coding: utf-8 -*-
"""Entry points that patched Seahub code calls into.

Keeping these in one module means the patches in seahub/ stay one-liners that
never need to know which capabilities exist -- adding a capability is a
registration, not another edit to upstream code.
"""

from cloudfile_ext.registry import registry


def check_permission(username, repo_id, path, permission):
    """Narrow `permission` through every registered permission hook.

    Called from seahub.views.check_folder_permission. Returns the permission
    unchanged when no capability has registered a hook, which is the case with
    every CF_ENABLE_* switch off.
    """
    if not registry.permission_checks:
        return permission
    return registry.apply_permission_checks(username, repo_id, path, permission)
