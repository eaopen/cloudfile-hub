"""Minimal same-transaction OIDC session references, never a user snapshot."""
from datetime import datetime, timezone
import hashlib
import re

from ..common.validation import identifier
from ..common.errors import ContractError
from ..jobs.store import canonical
from ..schema.runner import SchemaRunner
from .logout_token import LogoutNotification


class OIDCSessionIndex:
    def __init__(self, connection, *, issuer, client_id):
        SchemaRunner(connection).require_current()
        identifier(issuer)
        identifier(client_id)
        self.connection = connection
        self.issuer, self.client_id = issuer, client_id
        self.scope_hash = hashlib.sha256(canonical([issuer, client_id]).encode()).hexdigest()
        self.scope = dict(type="provider", provider="cf_oidc_" + self.scope_hash[:24],
            external_id="cf_oidc_" + self.scope_hash[:24])

    def _transaction(self, cursor):
        if cursor.connection is not self.connection:
            raise ValueError("index requires this owned SQL connection")
        cursor.execute("SELECT @@in_transaction")
        if cursor.fetchone() != (1,):
            raise ValueError("index effect requires the caller's actual transaction")

    @staticmethod
    def _hash(value):
        return hashlib.sha256(identifier(value).encode()).hexdigest()

    def register(self, cursor, *, session_key, subject, session_id, authenticated_at, expires_at):
        self._transaction(cursor)
        if (not isinstance(session_key, str) or not re.fullmatch(r"[a-z0-9]{32}", session_key)
                or type(authenticated_at) is not int or not 0 <= authenticated_at <= 2 ** 63 - 1
                or not isinstance(expires_at, datetime) or expires_at.tzinfo is None
                or expires_at.timestamp() <= authenticated_at):
            raise ValueError("valid native session reference required")
        targets = [("subject", self._hash(subject))]
        if session_id is not None:
            targets.append(("sid", self._hash(session_id)))
        for target_type, target_hash in sorted(targets):
            cursor.execute("SELECT cutoff_at FROM cf_oidc_logout_fence WHERE scope_hash=%s "
                "AND target_type=%s AND target_hash=%s FOR UPDATE", (self.scope_hash, target_type, target_hash))
            rows = cursor.fetchall()
            if rows and (len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] >= authenticated_at):
                raise ContractError("AUTHENTICATION_REQUIRED", "OIDC authentication was invalidated by logout", 401)
        cursor.execute("INSERT INTO cf_oidc_session(scope_hash,session_key,subject_hash,sid_hash,authenticated_at,expires_at) "
            "VALUES(%s,%s,%s,%s,%s,%s)", (self.scope_hash, session_key, self._hash(subject),
                None if session_id is None else self._hash(session_id), authenticated_at,
                expires_at.astimezone(timezone.utc).replace(tzinfo=None)))

    def fence(self, cursor, notification):
        self._transaction(cursor)
        if (not isinstance(notification, LogoutNotification)
                or (notification.issuer, notification.client_id) != (self.issuer, self.client_id)):
            raise ValueError("verified fixed-scope logout notification required")
        target_type = "sid" if notification.session_id is not None else "subject"
        value = notification.session_id if notification.session_id is not None else notification.subject
        cursor.execute("INSERT INTO cf_oidc_logout_fence(scope_hash,target_type,target_hash,cutoff_at,updated_at) "
            "VALUES(%s,%s,%s,%s,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE "
            "cutoff_at=GREATEST(cutoff_at,VALUES(cutoff_at)),updated_at=UTC_TIMESTAMP(6)",
            (self.scope_hash, target_type, self._hash(value), notification.issued_at))

    def targets(self, cursor, notification, *, limit=100):
        self._transaction(cursor)
        if (not isinstance(notification, LogoutNotification)
                or (notification.issuer, notification.client_id) != (self.issuer, self.client_id)
                or type(limit) is not int or not 1 <= limit <= 1000):
            raise ValueError("verified fixed-scope notification and bounded page required")
        if notification.session_id is not None:
            index, column, value = "oidc_sid", "sid_hash", notification.session_id
        elif notification.subject is not None:
            index, column, value = "oidc_subject", "subject_hash", notification.subject
        else:
            raise ValueError("logout target required")
        parameters = [self.scope_hash, self._hash(value), notification.issued_at]
        sql = ("SELECT session_key FROM cf_oidc_session FORCE INDEX (" + index + ") "
            "WHERE scope_hash=%s AND " + column + "=%s AND authenticated_at<=%s")
        if notification.subject is not None and notification.session_id is not None:
            sql += " AND subject_hash=%s"
            parameters.append(self._hash(notification.subject))
        sql += " ORDER BY authenticated_at,session_key LIMIT %s FOR UPDATE"
        parameters.append(limit)
        cursor.execute(sql, tuple(parameters))
        return tuple(row[0] for row in cursor.fetchall())

    def forget(self, cursor, session_key):
        self._transaction(cursor)
        if not isinstance(session_key, str) or not re.fullmatch(r"[a-z0-9]{32}", session_key):
            raise ValueError("valid native session key required")
        cursor.execute("DELETE FROM cf_oidc_session WHERE scope_hash=%s AND session_key=%s",
            (self.scope_hash, session_key))
