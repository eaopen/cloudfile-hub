"""Bounded expired-reference cleanup; never deletes logout fences or sessions."""
from ..jobs.authority import scope_locks
from .session_delete import NativeDBSessionDelete


class OIDCSessionRetention:
    def __init__(self, deletion):
        if not isinstance(deletion, NativeDBSessionDelete):
            raise ValueError("actual same-server native DB adapter required")
        self.deletion = deletion

    def run_once(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("bounded cleanup page required")
        index = self.deletion.index
        connection = index.connection
        removed = renewed = 0
        with scope_locks(connection, [index.scope]):
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    index._transaction(cursor)
                    cursor.execute("SELECT session_key FROM cf_oidc_session FORCE INDEX(oidc_scope_expiry) "
                        "WHERE expires_at<=UTC_TIMESTAMP(6) AND scope_hash=%s "
                        "ORDER BY expires_at,session_key LIMIT %s FOR UPDATE", (index.scope_hash, limit))
                    keys = tuple(row[0] for row in cursor.fetchall())
                    for key in keys:
                        cursor.execute("SELECT expire_date,expire_date>UTC_TIMESTAMP(6) FROM " +
                            self.deletion.table + " WHERE session_key=%s FOR UPDATE", (key,))
                        rows = cursor.fetchall()
                        if len(rows) > 1:
                            raise ValueError("ambiguous native session")
                        if rows and rows[0][1] == 1:
                            # Older indexes may predate saved sliding expiration.
                            # Retain the reference; this is not an auth grant.
                            cursor.execute("UPDATE cf_oidc_session SET expires_at=%s "
                                "WHERE scope_hash=%s AND session_key=%s", (rows[0][0], index.scope_hash, key))
                            renewed += 1
                        else:
                            index.forget(cursor, key)
                            removed += 1
                connection.commit()
            finally:
                connection.rollback()
        return dict(examined=len(keys), removed=removed, renewed=renewed)
