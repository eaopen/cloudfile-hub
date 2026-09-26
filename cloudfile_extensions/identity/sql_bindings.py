"""CE prebinding on the authority connection, without deferred ORM/RPC writes.

No JIT account creation or public management endpoint. Authorization and audit
must be supplied by trusted management adapters; audit uses the same cursor.
"""
import json

from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.project import qualified
from ..jobs.authority import scope_locks
from .bindings import IdentityBindings, conflict


class SQLIdentityBindings:
    def __init__(self, connection, *, native_schema, identity_schema, directory_provider,
                 authorize, audit):
        if not connection.get_autocommit() or not callable(authorize) or not callable(audit):
            raise ValueError("dedicated connection and trusted authorization/audit required")
        identifier(directory_provider, maximum=32)
        self.connection, self.provider = connection, directory_provider
        self.native_schema, self.identity_schema = native_schema, identity_schema
        self.accounts = qualified(native_schema, "EmailUser")
        self.profiles = qualified(identity_schema, "profile_profile")
        self.social = qualified(identity_schema, "social_auth_usersocialauth")
        self.authorize, self.audit = authorize, audit

    def _engines(self, cursor):
        for schema, table in ((self.native_schema, "EmailUser"),
                              (self.identity_schema, "profile_profile"),
                              (self.identity_schema, "social_auth_usersocialauth")):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (schema, table))
            if cursor.fetchall() != (("InnoDB",),):
                raise ValueError()
        for table, keys in (("profile_profile", {("user",), ("login_id",)}),
                            ("social_auth_usersocialauth", {("provider", "uid")})):
            cursor.execute("SELECT index_name,column_name,seq_in_index,sub_part FROM information_schema.statistics WHERE table_schema=%s AND table_name=%s AND non_unique=0 ORDER BY index_name,seq_in_index", (self.identity_schema, table))
            indexes = {}
            for name, column, sequence, prefix in cursor.fetchall():
                indexes.setdefault(name, []).append((column, sequence, prefix))
            complete = {tuple(row[0] for row in rows) for rows in indexes.values()
                        if all(row[1] == index + 1 and row[2] is None for index, row in enumerate(rows))}
            if not keys.issubset(complete):
                raise ValueError()

    def _account(self, cursor, username, *, locked=False):
        cursor.execute("SELECT email,is_active FROM " + self.accounts + " WHERE email=%s" + (" FOR UPDATE" if locked else ""), (username,))
        rows = cursor.fetchall()
        if (len(rows) != 1 or rows[0][0] != username or
                type(rows[0][1]) is not int or rows[0][1] not in (0, 1)):
            raise conflict()
        if rows[0][1] != 1:
            raise ContractError("SUBJECT_DISABLED", "Account is disabled", 403)

    @staticmethod
    def _social_match(rows, provider, subject, metadata, username=None):
        if not rows:
            return None
        if len(rows) != 1:
            raise conflict()
        actual_username, actual_provider, actual_subject, raw = rows[0]
        try:
            stored = json.loads(raw)
        except (ValueError, TypeError):
            raise conflict() from None
        if (actual_provider != provider or actual_subject != subject or stored != metadata or
                (username is not None and actual_username != username)):
            raise conflict()
        identifier(actual_username)
        return actual_username

    def resolve(self, *, issuer, subject, user_id):
        provider, metadata = IdentityBindings._identity(issuer, subject, user_id)
        try:
            with self.connection.cursor() as cursor:
                self._engines(cursor)
                cursor.execute("SELECT username,provider,uid,extra_data FROM " + self.social + " WHERE provider=%s AND uid=%s", (provider, subject))
                username = self._social_match(cursor.fetchall(), provider, subject, metadata)
                if username is None:
                    return None
                cursor.execute("SELECT user,login_id FROM " + self.profiles + " WHERE user=%s OR login_id=%s", (username, user_id))
                if cursor.fetchall() != ((username, user_id),):
                    raise conflict()
                self._account(cursor, username)
                return username
        except ContractError:
            raise
        except Exception as error:
            if getattr(error, "args", ()) and error.args[0] == 1062:
                raise conflict() from None
            raise ContractError("IDENTITY_UNAVAILABLE", "Identity binding is unavailable", 503) from None

    def prebind(self, *, issuer, subject, user_id, username, actor, reason):
        provider, metadata = IdentityBindings._identity(issuer, subject, user_id)
        identifier(username)
        identifier(actor, maximum=225)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
            raise ContractError("INVALID_REQUEST", "A bounded binding reason is required", 400)
        scopes = [dict(type="provider", provider=self.provider, external_id=self.provider),
                  dict(type="user", provider=self.provider, external_id=user_id),
                  dict(type="subject", provider=provider, namespace="oidc", external_id=subject)]
        try:
            with scope_locks(self.connection, scopes):
                self.connection.begin()
                try:
                    with self.connection.cursor() as cursor:
                        self._engines(cursor)
                        # Authorization may lock the current manager account;
                        # it must share this transaction, not use another RPC.
                        if self.authorize(cursor, actor, user_id, username) is not True:
                            raise ContractError("ACCESS_DENIED", "Identity management is denied", 403)
                        self._account(cursor, username, locked=True)
                        cursor.execute("SELECT user,login_id FROM " + self.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE", (username, user_id))
                        rows = cursor.fetchall()
                        if len(rows) != 1 or rows[0][0] != username or rows[0][1] not in (None, "", user_id):
                            raise conflict()
                        cursor.execute("SELECT username,provider,uid,extra_data FROM " + self.social + " WHERE provider=%s AND uid=%s FOR UPDATE", (provider, subject))
                        existing = self._social_match(cursor.fetchall(), provider, subject, metadata, username)
                        if existing is not None and rows[0][1] == user_id:
                            return username, False
                        cursor.execute("UPDATE " + self.profiles + " SET login_id=%s WHERE user=%s", (user_id, username))
                        if existing is None:
                            cursor.execute("INSERT INTO " + self.social + "(username,provider,uid,extra_data) VALUES(%s,%s,%s,%s)",
                                           (username, provider, subject, json.dumps(metadata, sort_keys=True)))
                        self.audit(cursor, dict(action="identity.bound", actor_user_id=actor,
                                                userId=user_id, username=username, reason=reason))
                    self.connection.commit()
                    return username, True
                finally:
                    self.connection.rollback()
        except ContractError:
            raise
        except Exception as error:
            if getattr(error, "args", ()) and error.args[0] == 1062:
                raise conflict() from None
            raise ContractError("IDENTITY_UNAVAILABLE", "Identity binding is unavailable", 503) from None
