"""Actual DB-session deletion on the job/index SQL, not a generic callback."""
from django.conf import settings

from ..common.errors import ContractError
from ..directory.project import qualified
from .native_session import BACKEND, SESSION_REFERENCE_KEY
from .session_index import OIDCSessionIndex
from .logout_token import LogoutNotification


class NativeDBSessionDelete:
    def __init__(self, index, *, identity_schema):
        if not isinstance(index, OIDCSessionIndex):
            raise ValueError("actual transactional session index required")
        if settings.SESSION_ENGINE != "django.contrib.sessions.backends.db":
            raise ContractError("IDENTITY_UNAVAILABLE", "Backchannel requires the database session backend", 503)
        from django.contrib.sessions.models import Session
        from django.contrib.sessions.backends.db import SessionStore
        from django.db import router, connections
        alias = router.db_for_write(Session)
        if connections[alias].settings_dict.get("NAME") != identity_schema:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native session schema does not match deployment", 503)
        self.index = index
        self.schema = identity_schema
        self.table_name = Session._meta.db_table
        self.table = qualified(identity_schema, self.table_name)
        self.decoder = SessionStore()

    def delete(self, cursor, session_key, notification):
        from seahub.auth import BACKEND_SESSION_KEY
        self.index._transaction(cursor)
        if (not isinstance(notification, LogoutNotification)
                or (notification.issuer, notification.client_id) != (self.index.issuer, self.index.client_id)):
            raise ValueError("verified fixed-scope logout target required")
        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s",
            (self.schema, self.table_name))
        if cursor.fetchall() != (("InnoDB",),):
            raise ContractError("IDENTITY_UNAVAILABLE", "Native session storage is unavailable", 503)
        cursor.execute("SELECT subject_hash,sid_hash,authenticated_at FROM cf_oidc_session "
            "WHERE scope_hash=%s AND session_key=%s FOR UPDATE", (self.index.scope_hash, session_key))
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native session reference changed", 503)
        subject, sid, issued = rows[0]
        if (type(issued) is not int or issued > notification.issued_at
                or (notification.subject is not None and subject != self.index._hash(notification.subject))
                or (notification.session_id is not None and sid != self.index._hash(notification.session_id))):
            raise ContractError("IDENTITY_UNAVAILABLE", "Native session logout target changed", 503)
        cursor.execute("SELECT session_data FROM " + self.table + " WHERE session_key=%s FOR UPDATE", (session_key,))
        sessions = cursor.fetchall()
        if len(sessions) > 1:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native session storage is ambiguous", 503)
        if sessions:
            data = self.decoder.decode(sessions[0][0])
            expected = dict(scope_hash=self.index.scope_hash, subject_hash=subject,
                sid_hash=sid, authenticated_at=issued)
            if (not isinstance(data, dict) or data.get(BACKEND_SESSION_KEY) != BACKEND
                    or data.get(SESSION_REFERENCE_KEY) != expected):
                raise ContractError("IDENTITY_UNAVAILABLE", "Signed native session reference does not match", 503)
            cursor.execute("DELETE FROM " + self.table + " WHERE session_key=%s", (session_key,))
        # A previously expired/deleted native session is already terminated;
        # remove its index on this exact same transaction, never a second DB.
        self.index.forget(cursor, session_key)
        return bool(sessions)
