# -*- coding: utf-8 -*-
"""Pure favorites-identity rules.

No Django, database, or Seafile imports -- this module must stay importable
without a running Seahub so it can be unit-tested directly and reused by
server-side consumers (cloudfile-hub/AGENTS.md rule 4).

A favorite ("starred item") is identified by the object's unique id: the
Seafile file obj_id or the directory id. ``repo_id`` and ``path`` remain on the
row only as the object's *current location*, so they can be refreshed on
move/rename without changing the favorite's identity.
"""


def pick_obj_id(file_id, dir_id):
    """Pick the object id from the two RPC lookups, file first.

    ``file_id``/``dir_id`` are the return values of
    ``get_file_id_by_path``/``get_dir_id_by_path``; either may be None.
    A path that resolves to neither has no object id.
    """
    return file_id or dir_id or None


def should_backfill(stored_obj_id, resolved_obj_id):
    """Whether a favorite row needs its obj_id backfilled.

    A row needs backfill when it has no stored obj_id but its stored path
    still resolves to one. Backfill is additive by construction -- it only
    fills the id, never deletes or rewrites a row -- so migrating old
    path-keyed records is lossless.
    """
    return not stored_obj_id and bool(resolved_obj_id)


def relocate_path(path, src_dir, dst_dir):
    """Return ``path`` relocated from ``src_dir`` to ``dst_dir``, or None.

    ``src_dir``/``dst_dir`` are normalised directory paths (with a trailing
    slash). ``path`` is a stored favorite path.

    * a path equal to ``src_dir`` (the moved directory itself) relocates to
      ``dst_dir`` (trailing slash stripped, matching how Seahub stores dirs);
    * a path strictly under ``src_dir`` keeps its relative suffix;
    * anything else returns None so the caller leaves unrelated rows alone.

    A trailing slash on ``src_dir`` makes the prefix test safe: ``/a/b`` does
    not match the sibling ``/a/bc.txt``.
    """
    if path == src_dir.rstrip('/'):
        return dst_dir.rstrip('/')
    if not path.startswith(src_dir):
        return None
    return dst_dir + path[len(src_dir):]
