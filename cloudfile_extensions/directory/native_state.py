"""Current SQL identity/account and durable subject-barrier reads.

No user snapshot, account creation, email fallback or readiness grant. Reads
are not substitutes for row locks and final checks in native effects.
"""
from ..common.errors import ContractError
from contextlib import contextmanager
from ..common.validation import identifier
from ..jobs.store import JobStore
from .project import qualified
from .coordinator import SQLRefreshGuard


class NativeSubjectState:
    def __init__(self, connection, *, native_schema, identity_schema, provider):
        if not connection.get_autocommit():
            raise ValueError("dedicated autocommit connection required")
        identifier(provider, maximum=32)
        self.connection, self.provider = connection, provider
        self.native_schema, self.identity_schema = native_schema, identity_schema
        self.accounts = qualified(native_schema, "EmailUser")
        self.profiles = qualified(identity_schema, "profile_profile")
        self.jobs = JobStore(connection)
        self.guard = SQLRefreshGuard(connection, provider=provider)

    @contextmanager
    def refresh_guard(self, user_id, epoch, *, phase):
        with self.guard(user_id, epoch, phase=phase) as proof:
            if phase != "fail" and self.barrier_active(self.provider, user_id):
                raise ContractError("SUBJECT_UNAVAILABLE", "Subject refresh is fenced", 503)
            yield proof

    def username(self, user_id):
        identifier(user_id, maximum=225)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name='profile_profile'",
                               (self.identity_schema,))
                if cursor.fetchall() != (("InnoDB",),):
                    raise ValueError()
                cursor.execute("SELECT user,login_id FROM " + self.profiles + " WHERE login_id=%s", (user_id,))
                rows = cursor.fetchall()
                if not rows:
                    raise ContractError("IDENTITY_NOT_FOUND", "Business identity has not been bound", 404)
                if len(rows) != 1 or rows[0][1] != user_id:
                    raise ValueError()
                username = rows[0][0]
                identifier(username)
                cursor.execute("SELECT user,login_id FROM " + self.profiles + " WHERE user=%s OR login_id=%s", (username, user_id))
                if cursor.fetchall() != ((username, user_id),):
                    raise ValueError()
                return username
        except ContractError:
            raise
        except Exception:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native identity is unavailable", 503) from None

    def user_id(self, native_username):
        """Reverse a native session account through the same business binding.

        Contact email, login form text and external employee number are not keys.
        The effect transaction still rechecks the two-axis binding and account.
        """
        identifier(native_username)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT user,login_id FROM " + self.profiles + " WHERE user=%s LIMIT 2", (native_username,))
                rows = cursor.fetchall()
            if not rows:
                raise ContractError("IDENTITY_NOT_FOUND", "Business identity has not been bound", 404)
            if len(rows) != 1 or rows[0][0] != native_username:
                raise ValueError()
            user_id = rows[0][1]
            identifier(user_id, maximum=225)
            if self.username(user_id) != native_username:
                raise ValueError()
            return user_id
        except ContractError:
            raise
        except Exception:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native identity is unavailable", 503) from None

    def account_active(self, user_id):
        try:
            username = self.username(user_id)
        except ContractError as error:
            if error.status == 404:
                return False
            raise
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name='EmailUser'", (self.native_schema,))
                if cursor.fetchall() != (("InnoDB",),):
                    raise ValueError()
                cursor.execute("SELECT email,is_active FROM " + self.accounts + " WHERE email=%s", (username,))
                rows = cursor.fetchall()
                if not rows:
                    return False
                if len(rows) != 1 or rows[0][0] != username or type(rows[0][1]) is not int or rows[0][1] not in (0, 1):
                    raise ValueError()
                return rows[0][1] == 1
        except Exception:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native account is unavailable", 503) from None

    def barrier_active(self, provider, user_id):
        identifier(user_id, maximum=225)
        if provider != self.provider:
            raise ContractError("SUBJECT_UNAVAILABLE", "Subject source is unavailable", 503)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_background_job'")
                if cursor.fetchall() != (("InnoDB",),):
                    raise ValueError()
            return any(self.jobs.active_barrier(scope) for scope in (
                dict(type="provider", provider=provider, external_id=provider),
                dict(type="user", provider=provider, external_id=user_id)))
        except Exception:
            raise ContractError("SUBJECT_UNAVAILABLE", "Subject barriers are unavailable", 503) from None
