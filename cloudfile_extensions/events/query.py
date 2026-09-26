"""Bounded internal audit reader; trusted current authorization is mandatory.

No HTTP endpoint, retention mutation or raw payload export is provided here.
Legacy rows keep their original identity instead of invented actor/event IDs.
"""

import base64
from datetime import timezone
import hashlib
import hmac
import json
import re
import time
from uuid import UUID

from ..common.errors import ContractError
from ..common.validation import identifier, utc_time
from ..resources.paths import normalize_path


def invalid():
    return ContractError("INVALID_REQUEST", "Invalid audit query or cursor", 400)


class AuditReader:
    FIELDS = ("id", "event_id", "schema_version", "occurred_at", "recorded_at",
              "repo_id", "resource_uid", "actor_user_id", "actor_kind", "delegator",
              "operator", "source", "operation", "result", "source_path", "target_path", "request_id")

    def __init__(self, connection, *, secret, authorize, clock=time.time):
        if not isinstance(secret, bytes) or len(secret) < 32 or not callable(authorize):
            raise ValueError("audit reader requires a signing key and trusted authorization")
        if not connection.get_autocommit():
            raise ValueError("audit reader requires a dedicated autocommit connection")
        self.connection, self.secret, self.authorize, self.clock = connection, secret, authorize, clock

    @staticmethod
    def _storage(sql):
        sql.execute("SELECT id FROM cf_audit_event LIMIT 0 FOR UPDATE")
        sql.fetchall()
        sql.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_audit_event'")
        if sql.fetchall() != (("InnoDB",),):
            raise ValueError("unsafe audit storage")
        for name, expected in (("PRIMARY", (("id", 0, None),)),
                ("audit_repo_page", (("repo_id", 1, None), ("occurred_at", 1, None), ("id", 1, None)))):
            sql.execute("SELECT column_name,non_unique,sub_part FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_audit_event' AND index_name=%s ORDER BY seq_in_index", (name,))
            if sql.fetchall() != expected:
                raise ValueError("invalid audit pagination index")

    def upper_bound(self):
        """Internal insertion cutoff, not a cross-request MVCC snapshot."""
        try:
            with self.connection.cursor() as sql:
                self._storage(sql)
                sql.execute("SELECT COALESCE(MAX(id),0) FROM cf_audit_event")
                return sql.fetchone()[0]
        except Exception:
            raise ContractError("AUDIT_UNAVAILABLE", "Audit storage is unavailable", 503) from None

    def _cursor(self, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self.secret, b"cf.audit.v1\n" + raw, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw + signature).decode().rstrip("=")

    def _position(self, cursor, scope):
        if cursor is None:
            return None, self.clock() + 900
        try:
            if not isinstance(cursor, str) or len(cursor) > 4096 or not re.fullmatch(r"[A-Za-z0-9_-]+", cursor):
                raise ValueError()
            signed = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            raw, signature = signed[:-32], signed[-32:]
            if not hmac.compare_digest(signature, hmac.new(self.secret, b"cf.audit.v1\n" + raw, hashlib.sha256).digest()):
                raise ValueError()
            value = json.loads(raw)
            if (set(value) != {"scope", "position", "expires"} or value["scope"] != scope or
                    type(value["expires"]) not in (int, float) or not self.clock() < value["expires"] <= self.clock() + 900):
                raise ValueError()
            position = value["position"]
            if not isinstance(position, list) or len(position) != 2 or type(position[1]) is not int or position[1] <= 0:
                raise ValueError()
            return (utc_time(position[0]).replace(tzinfo=None), position[1]), value["expires"]
        except (ValueError, TypeError, KeyError, ContractError):
            raise invalid() from None

    def list(self, *, actor, repo_id, start, end, limit=100, cursor=None,
             actor_user_id=None, action=None, result=None, path=None, resource_uid=None, upper_bound=None):
        identifier(actor)
        try:
            repo_id = str(UUID(repo_id))
            first, last = utc_time(start), utc_time(end)
            if not 0 < (last - first).total_seconds() <= 31 * 86400 or type(limit) is not int or not 1 <= limit <= 200:
                raise ValueError()
            if upper_bound is not None and (type(upper_bound) is not int or not 0 <= upper_bound <= 2 ** 63 - 1):
                raise ValueError()
            filters = {"actor": actor, "repo_id": repo_id, "start": first.isoformat(), "end": last.isoformat(),
                       "actor_user_id": actor_user_id, "action": action, "result": result, "path": path,
                       "resource_uid": str(UUID(resource_uid)) if resource_uid is not None else None,
                       "upper_bound": upper_bound}
            for name in ("actor_user_id", "action", "result"):
                if filters[name] is not None:
                    identifier(filters[name])
            if path is not None:
                filters["path"] = normalize_path(path, "dir")
        except (ValueError, TypeError, AttributeError, ContractError):
            raise invalid() from None
        scope = hashlib.sha256(json.dumps(filters, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        position, expiry = self._position(cursor, scope)
        # Trusted runtime must check current account/context and audit scope;
        # a signed cursor is not an authorization grant.
        if self.authorize(actor, {"repo_id": repo_id}) is not True:
            raise ContractError("FORBIDDEN", "Audit scope is not available", 403)
        clauses = ["repo_id=%s", "occurred_at>=%s", "occurred_at<%s"]
        values = [repo_id, first.replace(tzinfo=None), last.replace(tzinfo=None)]
        if upper_bound is not None:
            clauses.append("id<=%s")
            values.append(upper_bound)
        for name, column in (("actor_user_id", "actor_user_id"), ("action", "operation"),
                             ("result", "result"), ("resource_uid", "resource_uid")):
            if filters[name] is not None:
                clauses.append(column + "=%s")
                values.append(filters[name])
        if filters["path"] is not None:
            clauses.append("(source_path=%s OR target_path=%s)")
            values.extend([filters["path"], filters["path"]])
        if position is not None:
            clauses.append("(occurred_at<%s OR (occurred_at=%s AND id<%s))")
            values.extend([position[0], position[0], position[1]])
        # Scan at most 1000 candidates; no OFFSET, total, full table scan or
        # hidden-row count. A page may be empty yet have a continuation cursor.
        try:
            with self.connection.cursor() as sql:
                self._storage(sql)
                sql.execute("SELECT " + ",".join(self.FIELDS) + " FROM cf_audit_event FORCE INDEX (audit_repo_page) WHERE " +
                            " AND ".join(clauses) + " ORDER BY occurred_at DESC,id DESC LIMIT 1001", values)
                rows = sql.fetchall()
        except Exception:
            raise ContractError("AUDIT_UNAVAILABLE", "Audit storage is unavailable", 503) from None
        items, consumed = [], 0
        for row in rows[:1000]:
            event = dict(zip(self.FIELDS, row))
            consumed += 1
            # Both source and target paths remain in this object so native
            # authorization cannot accidentally leak the other side of a move.
            if self.authorize(actor, event) is True:
                for name in ("occurred_at", "recorded_at"):
                    if event[name] is not None:
                        event[name] = event[name].replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                event["id"] = str(event["id"])
                items.append(event)
            if len(items) == limit:
                break
        next_cursor = None
        if consumed and consumed < len(rows):
            row = rows[consumed - 1]
            next_cursor = self._cursor({"scope": scope, "expires": expiry,
                "position": [row[3].replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"), row[0]]})
        return {"items": items, "next_cursor": next_cursor}
