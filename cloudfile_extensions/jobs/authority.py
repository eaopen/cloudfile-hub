"""SQL-only scope serialization, not a projection or authorization proof.

The protected effect must use this exact connection. Never lend this guard to
another connection/RPC or treat it as a lease that permits deferred publication.
Native branch transactions use the same database/scopes/name encoding.
"""

from contextlib import contextmanager
import hashlib
import json

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields


def canonical_scope(scope):
    object_fields(scope, ("type", "provider", "external_id"), ("namespace",))
    if scope["type"] not in {"user", "subject", "repo", "provider"}:
        raise ContractError("INVALID_REQUEST", "Invalid job scope", 400)
    if scope["type"] == "subject" and "namespace" not in scope:
        raise ContractError("INVALID_REQUEST", "Subject scope requires namespace", 400)
    for value in scope.values():
        identifier(value)
    return json.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def lock_name(database, scope_json):
    # Newline is unambiguous: schema identifiers cannot contain a newline here.
    identifier(database, maximum=64)
    if "\n" in database:
        raise ValueError("invalid authority schema name")
    return "cf.auth." + hashlib.sha256((database + "\n" + scope_json).encode()).hexdigest()[:56]


@contextmanager
def scope_locks(connection, scopes, *, timeout=5):
    if type(timeout) is not int or not 0 <= timeout <= 5 or not 1 <= len(scopes) <= 16:
        raise ValueError("invalid authority lock configuration")
    values = {canonical_scope(scope) for scope in scopes}
    # Same order in native C: provider/user/subject before sorted repository IDs.
    rank = {"provider": 0, "user": 1, "subject": 1, "repo": 2}
    values = sorted(values, key=lambda value: (rank[json.loads(value)["type"]], value))
    acquired = []
    owner = None
    uncertain = False
    try:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT DATABASE(),CONNECTION_ID()")
                database, owner = cursor.fetchone()
                for value in values:
                    name = lock_name(database, value)
                    cursor.execute("SELECT GET_LOCK(%s,%s),CONNECTION_ID()", (name, timeout))
                    locked, actual = cursor.fetchone()
                    if actual != owner:
                        uncertain = True
                        raise ContractError("AUTHORITY_UNAVAILABLE", "Authority connection changed", 503)
                    if locked != 1:
                        raise ContractError("AUTHORITY_BUSY", "Authority scope is busy", 503)
                    acquired.append(name)
        except ContractError:
            raise
        except Exception:
            uncertain = True
            raise ContractError("AUTHORITY_UNAVAILABLE", "Authority scope is unavailable", 503) from None
        yield
    finally:
        try:
            if uncertain:
                raise RuntimeError("authority acquisition result is unknown")
            with connection.cursor() as cursor:
                for name in reversed(acquired):
                    cursor.execute("SELECT RELEASE_LOCK(%s),CONNECTION_ID()", (name,))
                    released, actual = cursor.fetchone()
                    if released != 1 or actual != owner:
                        raise RuntimeError("authority lock ownership lost")
        except Exception:
            # A connection with unknown locks must never return to a pool.
            try:
                connection.close()
            except Exception:
                pass
            raise ContractError("AUTHORITY_UNAVAILABLE", "Authority scope is unavailable", 503) from None
