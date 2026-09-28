# -*- coding: utf-8 -*-
"""Pure precheck policy for copy/move (P2-06).

No Django, database, or Seafile imports: this module is the shareable,
unit-testable core of the fileops capability. The HTTP/Seafile wiring lives in
``service.py`` and ``views.py``.

Semantics: ``cloudfile-docker/docs/features/fileops.md``. Permission levels
follow ``cloudfile-docker/docs/roles-semantics.md`` -- only CE's ``r``/``rw``/
``admin`` (plus ``none``) exist, so the five-level role model is never spoken
here.
"""

import hashlib
import posixpath

# -- conflict policy -------------------------------------------------------

#: ``rename`` keeps both by auto-renaming the incoming item; ``skip`` drops the
#: item into the failure list; ``overwrite`` replaces the destination. There is
#: deliberately no silent overwrite: the default is ``rename``.
CONFLICT_RENAME = 'rename'
CONFLICT_SKIP = 'skip'
CONFLICT_OVERWRITE = 'overwrite'
CONFLICT_POLICIES = (CONFLICT_RENAME, CONFLICT_SKIP, CONFLICT_OVERWRITE)
DEFAULT_CONFLICT_POLICY = CONFLICT_RENAME

# -- failure reasons -------------------------------------------------------

#: Whole-request rejections (surfaced as an HTTP error).
REASON_PERMISSION = 'permission'
REASON_CROSS_SPACE = 'cross_space'
REASON_CYCLIC = 'cyclic_move'
REASON_NOT_FOUND = 'not_found'
REASON_OVER_QUOTA = 'over_quota'

#: Per-item failures (surfaced in the ``failures`` list, not a 4xx).
REASON_OVER_SIZE = 'over_size'
REASON_OVER_DEPTH = 'over_depth'
REASON_NAME_CONFLICT = 'name_conflict'

#: Whole-request batch rejections.
REASON_OVER_COUNT = 'over_count'
REASON_OVER_BATCH_SIZE = 'over_batch_size'

# -- permission matrix -----------------------------------------------------

_PERM_READ = ('r', 'rw', 'admin')
_PERM_WRITE = ('rw', 'admin')


def source_perm_allows(operation, perm):
    """Whether ``perm`` lets ``operation`` read its source.

    copy needs read (``r`` suffices, matching CE's ``RepoPerm.can_copy``);
    move needs write (``rw`` or ``admin``) because it removes the item from the
    source parent.
    """
    if operation == 'copy':
        return perm in _PERM_READ
    if operation == 'move':
        return perm in _PERM_WRITE
    return False


def target_perm_allows(perm):
    """Whether ``perm`` lets a new item be created in the destination."""
    return perm in _PERM_WRITE


def check_permissions(operation, source_perm, target_perm, cross_owner,
                      source_admin):
    """Return a whole-request rejection reason, or None when permitted.

    ``cross_owner`` is True when the source and destination libraries have
    different owners ("cross-space"). A cross-space move is the one case that
    needs more than plain ``rw``: removing content from somebody else's space
    requires admin on the source. Same-owner moves only need ``rw``.
    """
    if not target_perm_allows(target_perm):
        return REASON_PERMISSION
    if not source_perm_allows(operation, source_perm):
        return REASON_PERMISSION
    if operation == 'move' and cross_owner and not source_admin:
        return REASON_CROSS_SPACE
    return None


# -- move cycle ------------------------------------------------------------

def check_move_cycle(src_parent_dir, src_name, dst_parent_dir, src_repo_id,
                     dst_repo_id):
    """True when the move is degenerate: same location or into its own subtree.

    Only same-repo moves can be cyclic; a cross-repo move cannot nest inside
    itself. Moving a folder back into the same parent (``src_parent ==
    dst_parent``) is rejected too -- it is a no-op the C layer cannot express.
    """
    if src_repo_id != dst_repo_id:
        return False
    if src_parent_dir == dst_parent_dir:
        return True
    src_path = posixpath.join(src_parent_dir, src_name)
    if dst_parent_dir == src_path or dst_parent_dir.startswith(src_path + '/'):
        return True
    return False


# -- limits ----------------------------------------------------------------

def check_single_file_size(size, limit):
    """True when a single file exceeds ``limit`` (0 = unlimited)."""
    return limit > 0 and size > limit


def check_folder_depth(depth, limit):
    """True when a folder tree is deeper than ``limit`` (0 = unlimited)."""
    return limit > 0 and depth > limit


def check_item_count(count, limit):
    """True when a batch carries more items than ``limit`` (0 = unlimited)."""
    return limit > 0 and count > limit


def check_batch_size(total, limit):
    """True when a batch's total size exceeds ``limit`` (0 = unlimited)."""
    return limit > 0 and total > limit


# -- name conflict ---------------------------------------------------------

def resolve_conflict(name, existing_names, policy):
    """Return the destination name, or None when the item is to be skipped.

    ``existing_names`` is the set of names already present in the destination
    parent. The default policy renames rather than overwrites, which is the
    "never a silent overwrite" contract from the review checklist.
    """
    if name not in existing_names:
        return name
    if policy == CONFLICT_SKIP:
        return None
    if policy == CONFLICT_OVERWRITE:
        return name
    return _next_available_name(name, existing_names)


def _next_available_name(name, existing_names):
    """Append a ``(n)`` counter before the extension until the name is free."""
    if '.' not in name:
        stem, ext = name, ''
    else:
        stem, _, ext = name.rpartition('.')
        ext = '.' + ext
    n = 1
    while True:
        candidate = '%s (%d)%s' % (stem, n, ext)
        if candidate not in existing_names:
            return candidate
        n += 1


# -- idempotency -----------------------------------------------------------

def build_idempotency_key(username, operation, src_repo_id, src_parent_dir,
                          src_names, dst_repo_id, dst_parent_dir):
    """Deterministic key for one copy/move intent.

    Sorted source names make the key independent of list order. A repeated
    click of the same button submits the same tuple and therefore maps to the
    same key, which is how the task table turns it into a no-op.
    """
    canonical = '|'.join([
        username,
        operation,
        src_repo_id,
        src_parent_dir,
        ','.join(sorted(src_names)),
        dst_repo_id,
        dst_parent_dir,
    ])
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
