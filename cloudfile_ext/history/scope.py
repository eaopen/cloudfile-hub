# -*- coding: utf-8 -*-
"""Pure folder-history scope matching (P2-10).

The review contract (docs/review-history-cases.json, history-006/007) is:
default folder history shows the folder itself plus its **direct children** and
never recurses deeper; the `current_folder_only` filter excludes even direct
children, keeping only changes to the folder itself.

Diff entries carry absolute paths; directories end with '/'. A rename ('mov')
carries both the old path (name) and the new path (new_name), so both are
checked: moving a file in or out of the scope counts as a hit.
"""


def touches_folder_paths(changed_paths, folder, current_folder_only=False):
    """Whether any (old_path, new_path) pair hits the folder scope.

    ``changed_paths`` is an iterable of ``(name, new_name)`` pairs where either
    element may be ``None``/``''``. The function is pure so it can be shared
    verbatim by the Hub view and its unit tests.
    """
    folder = folder.rstrip('/')
    if not folder:
        return False

    for name, new_name in changed_paths:
        for raw in (name, new_name):
            if not raw:
                continue
            path = raw.rstrip('/')
            if path == folder:
                # The folder itself changed (created/deleted/renamed).
                return True
            if path.startswith(folder + '/'):
                rest = path[len(folder) + 1:]
                if not current_folder_only and '/' not in rest:
                    # A direct child, and recursion is not disabled.
                    return True
    return False
