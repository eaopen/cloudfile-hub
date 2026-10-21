"""Bounded, read-only managed download reconciliation; no public route.

Missing terminal facts are unknown, never manufactured interrupted/completed
events. Scope is an authorized window and insertion cutoff, not all history.
"""
from datetime import datetime, timezone

from ..common.errors import ContractError
from ..common.validation import object_fields, utc_time
from .authorized_query import AuthorizedAuditQuery
from .service import AuditService


class ReadAuditReconciliation:
    def __init__(self, query):
        if type(query) is not AuthorizedAuditQuery:
            raise ValueError("actual owned audit query required")
        self.query = query

    def report(self, filters):
        object_fields(filters, ("repo_id", "start", "end"))
        filters = AuditService._filters(filters)
        repo = filters["repo_id"]
        # Fixed bounds are not caller-controlled scan or retention policy.
        with self.query.export_scope(repo):
            epoch = self.query.export_epoch(self.query.authority.actor, repo)
            cutoff = self.query.export_upper_bound(repo)
            rows, cursor = [], None
            complete = False
            for _ in range(5):
                page = self.query.export_page(filters, limit=200, cursor=cursor,
                    upper_bound=cutoff, expected_epoch=epoch)
                rows.extend(page["items"])
                cursor = page["next_cursor"]
                if cursor is None:
                    complete = True
                    break
            # Recheck even for an empty report before releasing accumulated
            # paths/identities. Permission version changes discard the report.
            if self.query.export_epoch(self.query.authority.actor, repo) != epoch:
                raise ContractError("SUBJECT_UNAVAILABLE", "Audit reconciliation subject changed", 503)
            return summarize_read_attempts(rows, filters=filters, cutoff=cutoff,
                complete=complete, now=datetime.now(timezone.utc))


def summarize_read_attempts(rows, *, filters, cutoff, complete, now):
    """Internal presentation only; inputs must already be authorized/redacted."""
    terminal = set()
    attempts = []
    for row in rows:
        if (row.get("schema_version") != 1 or row.get("source") != "fileserver"
                or row.get("operation") not in {"file.view", "file.download"}
                or not row.get("request_id") or row.get("actor_kind") != "user"):
            continue
        key = tuple(row.get(field) for field in
            ("request_id", "repo_id", "actor_user_id", "operation", "source_path"))
        if row.get("result") in {"succeeded", "stream_completed", "failed", "interrupted"}:
            terminal.add(key)
        elif row.get("result") == "attempted":
            attempts.append((key, row))
    unknown = []
    seen = set()
    for key, row in attempts:
        if key in terminal or key in seen:
            continue
        seen.add(key)
        occurred = utc_time(row["occurred_at"])
        # Fifteen minutes is only a reporting threshold, not proof of death.
        if (now - occurred).total_seconds() < 900:
            continue
        unknown.append({field: row.get(field) for field in
            ("event_id", "request_id", "repo_id", "actor_user_id", "operation", "source_path", "occurred_at")})
        unknown[-1]["state"] = "terminal_not_observed"
    return dict(items=unknown, window=dict(filters), upper_bound=str(cutoff),
        scan_complete=complete, meaning="No matching terminal in the authorized scanned window and insertion cutoff; delivery outcome is unknown")
