# -*- coding: utf-8 -*-
"""CloudFile audit events that seafevents' Activity cannot represent.

The Activity table (owned by seafevents, out of CloudFile's reach from the
Hub) records commit-diff file/directory operations. Repo tags have no such
producer -- they are only ever mutated through Seahub's ``repo-tags`` API -- so
a Hub-side hook on that endpoint captures *every* tag change with its
before/after values. This module is the writer for those events; it is a no-op
when ``CF_ENABLE_AUDIT`` is off and must never turn a tag operation into a
failure.
"""

import logging

logger = logging.getLogger(__name__)

# Source vocabulary. The first six are the review checklist's unified sources
# (couldfile_review20260814.md §5); ``commit`` is the seafevents commit-diff
# stream that the audit reader surfaces for file/directory operations, whose
# per-protocol origin (web/desktop/mobile) is not recoverable in the Hub.
SOURCE_WEB = 'web'
SOURCE_DESKTOP = 'desktop'
SOURCE_MOBILE = 'mobile'
SOURCE_API = 'api'
SOURCE_SYSTEM = 'system'
SOURCE_ADMIN = 'admin'
SOURCE_COMMIT = 'commit'

VALID_SOURCES = frozenset((
    SOURCE_WEB, SOURCE_DESKTOP, SOURCE_MOBILE, SOURCE_API,
    SOURCE_SYSTEM, SOURCE_ADMIN, SOURCE_COMMIT,
))

RESULT_SUCCESS = 'success'
RESULT_FAILURE = 'failure'
VALID_RESULTS = frozenset((RESULT_SUCCESS, RESULT_FAILURE))

# Tag operations the repo-tags endpoint writes.
OP_CREATE = 'create'
OP_UPDATE = 'update'
OP_DELETE = 'delete'


def tag_snapshot(repo_tag):
    """Plain-dict snapshot of a repo tag, used for before/after values.

    ``is_system`` is included so a system-tag change (create a system tag,
    delete one, or rename/recolour one) leaves its classification in the
    before/after pair, exactly as the review requires.
    """
    return {
        'repo_tag_id': repo_tag.pk,
        'repo_id': repo_tag.repo_id,
        'name': repo_tag.name,
        'color': repo_tag.color,
        'is_system': bool(repo_tag.is_system),
    }


def record_tag_event(operator, repo_id, operation, before=None, after=None,
                     source=SOURCE_API, result=RESULT_SUCCESS,
                     failure_reason=None):
    """Append a tag-change audit event. No-op when CF_ENABLE_AUDIT is off.

    A failed write is logged and swallowed by design: the audit trail is
    append-only best effort from the Hub's point of view, and a missing table
    or DB hiccup must never break the tag CRUD operation that produced it.
    """
    try:
        from cloudfile_ext.features import is_enabled
        if not is_enabled('CF_ENABLE_AUDIT'):
            return None
    except Exception as exc:  # pragma: no cover - import/switch wiring
        logger.warning('audit switch unavailable; skipping tag event: %s', exc)
        return None

    before_id = before.get('repo_tag_id') if before else None
    after_id = after.get('repo_tag_id') if after else None
    object_id = str(after_id if after_id is not None
                    else (before_id if before_id is not None else ''))

    try:
        from cloudfile_ext.audit.models import AuditEvent
        return AuditEvent.objects.append(
            object_type='tag',
            object_id=object_id,
            operation=operation,
            operator=operator or '',
            repo_id=repo_id or '',
            source=source,
            result=result,
            before=before,
            after=after,
            failure_reason=failure_reason,
        )
    except Exception as exc:
        logger.warning('failed to append tag audit event: %s', exc)
        return None
