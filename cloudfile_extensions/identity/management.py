"""Native administrator prebinding adapters, without an HTTP authentication route."""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.errors import ContractError
from ..common.validation import identifier
from ..directory.native_state import NativeSubjectState
from ..events.outbox import EventWriter
from ..schema.runner import SchemaRunner
from .sql_bindings import SQLIdentityBindings


class IdentityManagement:
    def __init__(self, connection, *, native_schema, identity_schema, directory_provider,
                 actor_user_id, request_id):
        identifier(actor_user_id, maximum=225)
        identifier(request_id)
        SchemaRunner(connection).require_current()
        self.actor = actor_user_id
        self.state = NativeSubjectState(connection, native_schema=native_schema,
                                       identity_schema=identity_schema, provider=directory_provider)
        writer = EventWriter()
        def authorize(cursor, actor, user_id, username):
            if actor != self.actor:
                return False
            manager = self.state.username(actor)
            cursor.execute("SELECT email,is_active,is_staff FROM " + self.state.accounts + " WHERE email=%s FOR UPDATE", (manager,))
            if cursor.fetchall() != ((manager, 1, 1),):
                return False
            # Recheck exact binding while native suspension/demotion is locked.
            cursor.execute("SELECT user,login_id FROM " + self.state.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE", (manager, actor))
            if cursor.fetchall() != ((manager, actor),):
                return False
            if self.state.barrier_active(directory_provider, actor) or self.state.barrier_active(directory_provider, user_id):
                raise ContractError("SUBJECT_UNAVAILABLE", "Identity management is fenced", 503)
            return True
        def audit(cursor, event):
            writer.append(cursor, dict(event_id=str(uuid4()),
                occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                request_id=request_id, actor_user_id=self.actor, actor_kind="user", source="hub",
                action="identity.bound", result="succeeded", target_user_id=event["userId"], reason=event["reason"]))
        self.bindings = SQLIdentityBindings(connection, native_schema=native_schema,
            identity_schema=identity_schema, directory_provider=directory_provider,
            authorize=authorize, audit=audit)

    def prebind(self, *, issuer, subject, user_id, username, reason):
        return self.bindings.prebind(issuer=issuer, subject=subject, user_id=user_id,
                                    username=username, actor=self.actor, reason=reason)
