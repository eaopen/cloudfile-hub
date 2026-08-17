# -*- coding: utf-8 -*-
"""Pure audit-query contract, kept independent of Django for unit tests.

The audit reader merges two sources:

* seafevents' ``Activity`` table (seahub-db) for file/directory commit-diff
  operations. Those rows carry no ``source``/``result`` columns, so the reader
  surfaces them as ``source='commit'`` and ``result='success'`` -- a committed,
  diffed operation is by definition successful, and the per-protocol origin is
  not recoverable in the Hub.
* CloudFile's ``cf_audit_event`` sidecar (seafile-db) for tag changes, which
  do carry explicit ``source``/``result``/``before``/``after``.

Everything in this module operates on plain values so it can be unit-tested
without a Django or database import.
"""

import datetime
import json

from cloudfile_ext.audit.events import (
    RESULT_SUCCESS, SOURCE_COMMIT, VALID_RESULTS, VALID_SOURCES,
)

# Operation vocabulary. ``update`` exists for the repo-tag rename/recolour
# path; Activity only ever emits create/edit/delete/rename/move/recover.
VALID_OPS = frozenset((
    'create', 'edit', 'update', 'delete', 'rename', 'move', 'recover'))
VALID_OBJECTS = frozenset(('file', 'dir', 'tag'))

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50

# cf_audit_event column order used by the ORM ``values_list`` query. Keep in
# lockstep with the model and the docker bootstrap DDL.
AUDIT_EVENT_COLUMNS = (
    'id', 'repo_id', 'object_type', 'object_id', 'operation', 'operator',
    'source', 'before', 'after', 'source_path', 'target_path', 'result',
    'failure_reason', 'occurred_at',
)


def _naive_utc_from_timestamp(value):
    return datetime.datetime.fromtimestamp(
        value, datetime.timezone.utc).replace(tzinfo=None)


def parse_time(value, name):
    """Parse a time filter as epoch seconds or ISO-8601; None when absent."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return _naive_utc_from_timestamp(int(text))
    except (TypeError, ValueError):
        pass
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.datetime.fromisoformat(text).replace(tzinfo=None)
    except (ValueError, AttributeError):
        pass
    raise ValueError('%s invalid; use epoch seconds or ISO-8601.' % name)


def parse_filters(params):
    """Validate and normalize query params. Raises ValueError (400-ready)."""
    try:
        page = max(1, int(params.get('page', '1')))
        per_page = min(MAX_PAGE_SIZE, max(
            1, int(params.get('per_page', str(DEFAULT_PAGE_SIZE)))))
    except (TypeError, ValueError):
        raise ValueError('page or per_page invalid.')

    spec = {
        'page': page,
        'per_page': per_page,
        'repo_id': (params.get('repo_id') or '').strip() or None,
        'user': (params.get('user') or '').strip() or None,
        'path': (params.get('path') or '').strip() or None,
        'source': (params.get('source') or '').strip() or None,
        'result': (params.get('result') or '').strip() or None,
        'op_type': (params.get('op_type') or '').strip() or None,
        'obj_type': (params.get('obj_type') or '').strip() or None,
        'start': parse_time(params.get('start'), 'start'),
        'end': parse_time(params.get('end'), 'end'),
    }

    if spec['op_type'] and spec['op_type'] not in VALID_OPS:
        raise ValueError('op_type invalid.')
    if spec['obj_type'] and spec['obj_type'] not in VALID_OBJECTS:
        raise ValueError('obj_type invalid.')
    if spec['source'] and spec['source'] not in VALID_SOURCES:
        raise ValueError('source invalid.')
    if spec['result'] and spec['result'] not in VALID_RESULTS:
        raise ValueError('result invalid.')
    if spec['start'] and spec['end'] and spec['start'] > spec['end']:
        raise ValueError('start must not be after end.')
    return spec


def activity_where(spec):
    """Build the Activity WHERE clause and params for a filter spec.

    Activity has no ``source``/``result`` columns: every row is a committed
    operation surfaced as ``source='commit'``/``result='success'``, so a
    source/result filter that names a different value matches nothing here.
    """
    clauses, values = [], []
    if spec['repo_id']:
        clauses.append('repo_id = %s')
        values.append(spec['repo_id'])
    if spec['user']:
        clauses.append('op_user = %s')
        values.append(spec['user'])
    if spec['op_type']:
        clauses.append('op_type = %s')
        values.append(spec['op_type'])
    if spec['obj_type']:
        clauses.append('obj_type = %s')
        values.append(spec['obj_type'])
    else:
        # Activity also records library lifecycle rows; the operation log is
        # scoped to file/directory objects unless a tag filter is requested.
        clauses.append('obj_type IN (%s, %s)')
        values.extend(('file', 'dir'))
    if spec['path']:
        clauses.append('(path LIKE %s OR detail LIKE %s)')
        values.extend(('%%%s%%' % spec['path'], '%%%s%%' % spec['path']))
    if spec['source'] and spec['source'] != SOURCE_COMMIT:
        clauses.append('1 = 0')
    if spec['result'] and spec['result'] != RESULT_SUCCESS:
        clauses.append('1 = 0')
    if spec['start']:
        clauses.append('timestamp >= %s')
        values.append(spec['start'])
    if spec['end']:
        clauses.append('timestamp <= %s')
        values.append(spec['end'])
    return clauses, values


def _iso(value):
    if isinstance(value, datetime.datetime):
        return value.strftime('%Y-%m-%dT%H:%M:%S')
    return value


def serialize_activity(row):
    """Map an Activity row to the unified event dict.

    ``row`` is the 9-tuple selected by the reader: (id, op_type, obj_type,
    op_user, timestamp, repo_id, commit_id, path, detail).
    """
    detail = json.loads(row[8] or '{}') if isinstance(row[8], str) else (row[8] or {})
    # seafevents writes a single-op detail as a dict and a batch-op detail as
    # a list. Surface the first item's old_path for batch ops rather than
    # crashing on .get.
    if isinstance(detail, list):
        first = detail[0] if detail else {}
        old_path = first.get('old_path', '') if isinstance(first, dict) else ''
    elif isinstance(detail, dict):
        old_path = detail.get('old_path', '')
    else:
        old_path = ''
    return {
        'id': row[0],
        'event_id': 'activity-%s' % row[0],
        'operation': row[1],
        'object_type': row[2],
        'user': row[3],
        'time': _iso(row[4]),
        'repo_id': row[5],
        'commit_id': row[6],
        'path': row[7],
        'old_path': old_path,
        'source': SOURCE_COMMIT,
        'result': RESULT_SUCCESS,
        'before': None,
        'after': None,
        'failure_reason': None,
        'detail': detail,
    }


def serialize_audit_event(row):
    """Map a cf_audit_event row to the unified event dict.

    ``row`` follows AUDIT_EVENT_COLUMNS: (id, repo_id, object_type, object_id,
    operation, operator, source, before, after, source_path, target_path,
    result, failure_reason, occurred_at).
    """
    def loads(value):
        try:
            return json.loads(value) if value else None
        except (TypeError, ValueError):
            return None

    before = loads(row[7])
    after = loads(row[8])
    return {
        'id': row[0],
        'event_id': 'audit-%s' % row[0],
        'operation': row[4],
        'object_type': row[2],
        'object_id': row[3],
        'user': row[5],
        'time': _iso(row[13]),
        'repo_id': row[1],
        'commit_id': None,
        'path': row[9] or row[10] or '',
        'old_path': row[9] if row[10] else '',
        'source': row[6],
        'result': row[11],
        'before': before,
        'after': after,
        'failure_reason': row[12],
        'detail': {},
    }


def merge_and_paginate(activity_rows, audit_rows, spec):
    """Merge the two sources by time and paginate in Python.

    The two tables live in different databases, so a SQL UNION is impossible;
    the reader fetches all *filtered* rows from each and sorts here. The
    filtered set is bounded by the admin-facing filter spec, and this keeps
    pagination correct across the merge point.
    """
    events = []
    for row in activity_rows:
        events.append((row[4], row[0], serialize_activity(row)))
    for row in audit_rows:
        events.append((row[13], row[0], serialize_audit_event(row)))
    events.sort(key=lambda item: (item[0], item[1]), reverse=True)
    total = len(events)
    start = (spec['page'] - 1) * spec['per_page']
    page = [item[2] for item in events[start:start + spec['per_page']]]
    return {
        'events': page,
        'total': total,
        'page': spec['page'],
        'per_page': spec['per_page'],
    }
