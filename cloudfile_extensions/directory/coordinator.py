"""Same-connection subject refresh guard; no public readiness grant."""
from contextlib import contextmanager

from ..common.errors import ContractError
from ..common.validation import identifier
from ..jobs.authority import canonical_scope, lock_name, scope_locks


class SQLRefreshGuard:
    def __init__(self, connection, *, provider):
        identifier(provider, maximum=32)
        if not connection.get_autocommit():
            raise ValueError("dedicated autocommit connection required")
        self.connection, self.provider = connection, provider

    @contextmanager
    def __call__(self, user_id, epoch, *, phase):
        identifier(user_id, maximum=225)
        if phase not in {"begin", "publish", "fail"}:
            raise ValueError("invalid refresh phase")
        scopes = [dict(type="provider", provider=self.provider, external_id=self.provider),
                  dict(type="user", provider=self.provider, external_id=user_id)]
        with scope_locks(self.connection, scopes):
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT DATABASE(),CONNECTION_ID()")
                database, owner = cursor.fetchone()
            names = [lock_name(database, canonical_scope(scope)) for scope in scopes]
            def assert_owner():
                try:
                    with self.connection.cursor() as cursor:
                        for name in names:
                            cursor.execute("SELECT IS_USED_LOCK(%s),CONNECTION_ID()", (name,))
                            if cursor.fetchone() != (owner, owner):
                                raise ValueError()
                except Exception:
                    raise ContractError("AUTHORITY_UNAVAILABLE", "Refresh authority is unavailable", 503) from None
            assert_owner()
            yield assert_owner
            assert_owner()
