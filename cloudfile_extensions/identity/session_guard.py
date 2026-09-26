"""Hold native identity and current subject checks around trusted finalization.

This guard is not authentication and must never be exposed as a DTO endpoint.
Only a native callback that has completed actual OIDC verification may use it.
"""
from contextlib import contextmanager
import time

from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from ..jobs.authority import scope_locks
from .login import PreparedLogin


@contextmanager
def prepared_session_guard(preparation, prepared):
    if (not isinstance(preparation, SubjectPreparation) or not isinstance(prepared, PreparedLogin)
            or preparation.actor != prepared.user_id):
        raise ValueError("actual own-subject preparation and trusted prepared login required")
    state = preparation.state
    connection = state.connection
    scopes = [dict(type="provider", provider=state.provider, external_id=state.provider),
              dict(type="user", provider=state.provider, external_id=prepared.user_id)]
    def check(cursor):
        if type(prepared.expires_at) is not int or prepared.expires_at <= time.time():
            raise ContractError("AUTHENTICATION_REQUIRED", "OIDC authentication expired before session creation", 401)
        for schema, table in ((state.native_schema, "EmailUser"),
                              (state.identity_schema, "profile_profile")):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s",
                (schema, table))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("IDENTITY_UNAVAILABLE", "Session identity storage is unavailable", 503)
        cursor.execute("SELECT user,login_id FROM " + state.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE",
            (prepared.username, prepared.user_id))
        if cursor.fetchall() != ((prepared.username, prepared.user_id),):
            raise ContractError("IDENTITY_UNAVAILABLE", "Session identity changed", 503)
        cursor.execute("SELECT email,is_active FROM " + state.accounts + " WHERE email=%s FOR UPDATE",
            (prepared.username,))
        if cursor.fetchall() != ((prepared.username, 1),):
            raise ContractError("ACCESS_DENIED", "Session account is inactive or unavailable", 403)
        current = preparation.contexts.current(prepared.user_id)
        if current is None or current["context_epoch"] != prepared.context_epoch:
            raise ContractError("SUBJECT_UNAVAILABLE", "Session subject changed", 503)
    if not connection.get_autocommit():
        raise ValueError("owned autocommit login connection required")
    with scope_locks(connection, scopes):
        connection.begin()
        try:
            with connection.cursor() as cursor:
                check(cursor)
                yield cursor
                # The host must not emit session cookies until this exits;
                # Redis expiry can change without taking SQL row locks.
                check(cursor)
            connection.commit()
        finally:
            connection.rollback()
