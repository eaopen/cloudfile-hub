# -*- coding: utf-8 -*-
"""Keep directory ACL rules attached to the object they were set on.

Why this exists
---------------
``cf_dir_acl`` / ``cf_dir_admin`` address their target by **path**. Until now
nothing moved those rows when the object moved: renaming or relocating a folder
in Seafile (from the portal, WebDAV or the desktop client) silently left its
rules behind on a path that no longer exists. The rule then keeps looking
configured in the admin screen while enforcing nothing -- the same silent class
of failure as the file-level-grant and no-eligibility cases, only triggered by a
rename instead of by the original write.

Design
------
Rename/move is observed the same way the search indexer observes commits: the
``Activity`` table written by seafevents, whose batch detail carries
``path``/``old_path`` per item. That source covers every client (the change is a
commit), needs no upstream edit, and shares the search indexer's failure model
--- best-effort, lagging by one tick, resumable from a watermark.

The watermark reuses ``cf_search_index_state`` (a generic ``(name, cursor)`` row)
under its own name, so no new table/DDL is introduced. The acl capability
therefore depends on that model existing, which it does whenever the
``cloudfile_ext`` app is installed (the model is part of the app, independently
of whether a search provider is selected).
"""

import json
import logging

from cloudfile_ext.acl import resolver

logger = logging.getLogger(__name__)

#: Watermark row name -- distinct from the search indexer's.
STATE_NAME = 'acl-path-migration'

#: Op types that can move a rule's target. `batch_*` prefixes are normalised
#: away by seafevents; both spellings are accepted below.
MOVING_OPS = frozenset(('rename', 'move'))

#: One tick's ceiling, matching the indexer's reasoning: bounded work per run,
#: resume from the watermark next time.
BATCH_SIZE = 500


def normalize_op(op_type):
    """seafevents merges consecutive commits into ``batch_<op>`` rows."""
    op_type = op_type or ''
    if op_type.startswith('batch_'):
        return op_type[len('batch_'):]
    return op_type


def rewrite_path(path, old_path, new_path):
    """The rule's new path after ``old_path`` became ``new_path``, or None.

    Covers both shapes with one rule: an exact match (the object itself, e.g. a
    file or a folder rename) and a prefix match (rules set on descendants of a
    moved folder). Anything else is left alone.
    """
    if path is None or old_path is None or new_path is None:
        return None
    path = resolver.normalize_path(path)
    old_path = resolver.normalize_path(old_path)
    new_path = resolver.normalize_path(new_path)
    if path == old_path:
        return new_path
    prefix = old_path.rstrip('/') + '/'
    if path.startswith(prefix):
        suffix = path[len(prefix):]
        return (new_path.rstrip('/') + '/' + suffix) if new_path != '/' else '/' + suffix
    return None


def plan_migration(rule_paths, old_path, new_path):
    """``[(old, new)]`` for every rule path affected by this move (pure)."""
    plan = []
    for path in rule_paths:
        target = rewrite_path(path, old_path, new_path)
        if target is not None and target != path:
            plan.append((path, target))
    return plan


def moved_entries(event):
    """``[(repo_id, old_path, new_path)]`` for one Activity row.

    Mirrors the search indexer's parsing: a batch row carries a list of items in
    its detail, a single-op row carries the path on the row itself and the old
    path inside the detail.
    """
    if normalize_op(event.get('op_type')) not in MOVING_OPS:
        return []
    repo_id = event.get('repo_id')
    detail = event.get('detail')
    entries = []
    if isinstance(detail, list):
        for item in detail:
            if not isinstance(item, dict):
                continue
            entries.append((repo_id, item.get('old_path'), item.get('path')))
    elif isinstance(detail, dict):
        entries.append((repo_id, detail.get('old_path'), event.get('path')))
    else:
        entries.append((repo_id, event.get('path'), None))
    # A move without an old path tells us nothing to migrate.
    return [(repo, old, new) for repo, old, new in entries if repo and old and new]


def migrate_path(repo_id, old_path, new_path):
    """Move every ACL rule and dir-admin grant under ``old_path`` (DB write).

    Returns the number of rows touched. Failures are logged and swallowed: a
    move that already happened must not be reported as failed because a
    bookkeeping row could not be rewritten -- the next tick retries, since the
    watermark is not advanced past a failed batch.
    """
    from cloudfile_ext.acl.models import DirACL, DirAdmin

    changed = 0
    for model in (DirACL, DirAdmin):
        rows = list(model.objects.filter(repo_id=repo_id).filter(
            path=old_path) | model.objects.filter(repo_id=repo_id).filter(
            path__startswith=old_path.rstrip('/') + '/'))
        for row in rows:
            target = rewrite_path(row.path, old_path, new_path)
            if target is None or target == row.path:
                continue
            # Saving through the model keeps path and path_hash in lockstep
            # (DirACL.save recomputes the hash); a queryset .update() would not.
            row.path = target
            row.save()
            changed += 1
    return changed


def _activities_since(cursor, limit):
    """Activity rows after ``cursor`` -- same query shape as the indexer."""
    from django.db import connection
    with connection.cursor() as db_cursor:
        db_cursor.execute(
            'SELECT id, op_type, obj_type, op_user, timestamp, repo_id, path, '
            'detail FROM Activity WHERE id > %s ORDER BY id ASC LIMIT %s',
            [cursor, limit])
        rows = db_cursor.fetchall()
    events = []
    for row in rows:
        events.append({
            'id': row[0], 'op_type': row[1], 'obj_type': row[2],
            'op_user': row[3], 'timestamp': row[4], 'repo_id': row[5],
            'path': row[6], 'detail': json.loads(row[7] or '{}'),
        })
    return events


def migration_tick(state_model=None, activities_since=None, migrate=None):
    """One pass: consume rename/move activity and rewrite affected rules.

    Injection points (``state_model``/``activities_since``/``migrate``) keep the
    tick testable without Django -- see
    ``cloudfile_ext/acl/tests/test_migration.py``.
    """
    if state_model is None:
        from cloudfile_ext.search.models import SearchIndexState as state_model
    activities_since = activities_since or _activities_since
    migrate = migrate or migrate_path

    cursor = state_model.objects.get_cursor(STATE_NAME)
    events = activities_since(cursor, BATCH_SIZE)
    if not events:
        return 0

    changed = 0
    touched_repos = set()
    for event in events:
        for repo_id, old_path, new_path in moved_entries(event):
            try:
                changed += migrate(repo_id, old_path, new_path)
                touched_repos.add(repo_id)
            except Exception:
                # Do not advance past a failed row: next tick retries it.
                logger.exception(
                    'acl path migration failed for %s %s -> %s; watermark not advanced',
                    repo_id, old_path, new_path)
                state_model.objects.advance(
                    STATE_NAME, cursor, 'error',
                    'failed at activity id %s' % event.get('id'))
                return changed

    if touched_repos:
        # Rules are cached per repo (TTL); a stale cache would keep serving the
        # pre-move decision for up to CF_ACL_CACHE_TTL seconds.
        try:
            from cloudfile_ext.acl import service
            for repo_id in touched_repos:
                service.invalidate_repo(repo_id)
        except Exception:
            logger.warning('acl path migration: cache invalidation failed',
                           exc_info=True)

    last_id = events[-1]['id']
    state_model.objects.advance(STATE_NAME, last_id, 'ok',
                                'migrated %d rules' % changed)
    return changed
