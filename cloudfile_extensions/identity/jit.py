"""Configured new-user JIT identity transaction; never reactivates existing users.

Only a trusted OIDC callback may call ensure. Native identity/profile/social
rows and audit are locally atomic; directory projection/Redis ready are later
steps, so this result is not a login session or file authorization.
"""
import json
import secrets
import time
from datetime import datetime, timezone
from uuid import uuid4

from ..common.errors import ContractError
from ..common.http import trusted_https_url
from ..directory.provider import DirectoryProvider
from ..directory.native_state import NativeSubjectState
from ..events.outbox import EventWriter
from ..jobs.authority import scope_locks
from ..schema.runner import SchemaRunner
from .bindings import IdentityBindings, conflict
from .sql_bindings import SQLIdentityBindings


class SQLJITProvisioner:
    def __init__(self, bindings, *, issuer, directory, enabled, request_id):
        if not isinstance(bindings, SQLIdentityBindings) or not isinstance(directory, DirectoryProvider) or type(enabled) is not bool:
            raise ValueError("native binding and trusted source configuration required")
        from ..common.validation import identifier
        identifier(request_id)
        self.bindings, self.directory, self.enabled = bindings, directory, enabled
        self.issuer, self.request_id = trusted_https_url(issuer), request_id
        SchemaRunner(bindings.connection).require_current()
        self.state = NativeSubjectState(bindings.connection, native_schema=bindings.native_schema,
                                       identity_schema=bindings.identity_schema, provider=bindings.provider)

    def ensure(self, identity, *, assert_transaction=None, request_id=None):
        from ..common.validation import identifier
        request_id = self.request_id if request_id is None else identifier(request_id)
        if assert_transaction is not None and not callable(assert_transaction):
            raise ValueError("trusted transaction assertion required")
        if not self.enabled or identity.get("issuer") != self.issuer:
            raise ContractError("ACCESS_DENIED", "Identity provisioning is not enabled", 403)
        user_id, subject = identity["userId"], identity["sub"]
        provider, metadata = IdentityBindings._identity(self.issuer, subject, user_id)
        existing = self.bindings.resolve(issuer=self.issuer, subject=subject, user_id=user_id)
        if existing is not None:
            return existing
        # Coherent primary fetch outside the short SQL authority transaction.
        source = self.directory.fetch(user_id)
        if source["status"] != "active":
            raise ContractError("SUBJECT_DISABLED", "Business subject is disabled", 403)
        # Employee numbers name new EAP accounts only; login_id remains the UID.
        # Generic directories without this attribute retain opaque account names.
        employee = source["attributes"].get("employee_no")
        if employee is not None:
            if (not isinstance(employee, str) or not employee or len(employee) > 200
                    or not all(c.isascii() and (c.isalnum() or c in "._-") for c in employee)
                    or employee.lower() == "cfadmin"):
                raise conflict()
        default_username = employee + "@auth.local" if employee else secrets.token_hex(16) + "@auth.local"
        connection = self.bindings.connection
        scopes = [dict(type="provider", provider=self.bindings.provider, external_id=self.bindings.provider),
                  dict(type="user", provider=self.bindings.provider, external_id=user_id),
                  dict(type="subject", provider=provider, namespace="oidc", external_id=subject)]
        try:
            with scope_locks(connection, scopes):
                if self.state.barrier_active(self.bindings.provider, user_id):
                    raise ContractError("SUBJECT_UNAVAILABLE", "Identity provisioning is fenced", 503)
                existing = self.bindings.resolve(issuer=self.issuer, subject=subject, user_id=user_id)
                if existing is not None:
                    return existing
                connection.begin()
                try:
                    with connection.cursor() as cursor:
                        self.bindings._engines(cursor)
                        if assert_transaction is not None:
                            assert_transaction(cursor)
                        cursor.execute("SELECT user,login_id FROM " + self.bindings.profiles + " WHERE login_id=%s FOR UPDATE", (user_id,))
                        profiles = cursor.fetchall()
                        if profiles:
                            # A verified UID may reuse its exact active native account.
                            # Never rename existing users or revive suspended accounts.
                            if len(profiles) != 1 or profiles[0][1] != user_id:
                                raise conflict()
                            username = profiles[0][0]
                            if username.lower() in ("cfadmin@etech.com", "cfadmin@auth.local"):
                                raise conflict()
                            self.bindings._account(cursor, username, locked=True)
                        else:
                            username = default_username
                            cursor.execute("SELECT user,login_id FROM " + self.bindings.profiles + " WHERE user=%s FOR UPDATE", (username,))
                            if cursor.fetchall():
                                # A name collision or changed UID requires explicit prebinding.
                                raise conflict()
                            cursor.execute("SELECT email FROM " + self.bindings.accounts + " WHERE email=%s FOR UPDATE", (username,))
                            if cursor.fetchall():
                                raise conflict()
                            cursor.execute("INSERT INTO " + self.bindings.accounts + "(email,passwd,is_staff,is_active,ctime) VALUES(%s,'!',0,1,%s)",
                                           (username, time.time_ns() // 1000))
                            cursor.execute("INSERT INTO " + self.bindings.profiles + "(user,nickname,intro,lang_code,login_id,contact_email,is_manually_set_contact_email,institution,list_in_address_book) VALUES(%s,'','',NULL,%s,NULL,0,'',0)", (username, user_id))
                        cursor.execute("INSERT INTO " + self.bindings.social + "(username,provider,uid,extra_data) VALUES(%s,%s,%s,%s)",
                                       (username, provider, subject, json.dumps(metadata, sort_keys=True)))
                        EventWriter().append(cursor, dict(event_id=str(uuid4()),
                            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            request_id=request_id, actor_user_id=user_id, actor_kind="user", source="idp",
                            # Reusing a Profile binds OIDC; it does not create a native account.
                            action="identity.bound" if profiles else "identity.created",
                            result="succeeded", target_user_id=user_id))
                        if assert_transaction is not None:
                            assert_transaction(cursor)
                    connection.commit()
                    return username
                finally:
                    connection.rollback()
        except ContractError:
            raise
        except Exception:
            raise ContractError("IDENTITY_UNAVAILABLE", "Identity provisioning is unavailable", 503) from None
