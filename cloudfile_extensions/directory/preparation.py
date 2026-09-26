"""Request-scoped own-user subject preparation with real SQL/Redis adapters.

Caller supplies an already authenticated business actor and machine directory
provider. Not an HTTP authentication mechanism or native access permission.
"""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.errors import ContractError
from ..common.validation import identifier
from ..events.outbox import EventWriter
from ..schema.runner import SchemaRunner
from .contexts import SubjectContexts
from .native_state import NativeSubjectState
from .project import NativeMembershipProjector
from .provider import DirectoryProvider


class SubjectPreparation:
    def __init__(self, connection, redis, *, provider_id, directory,
                 native_schema, identity_schema, actor_user_id, request_id,
                 prefix="cf:subjects:"):
        identifier(actor_user_id, maximum=225)
        identifier(request_id)
        if not isinstance(directory, DirectoryProvider):
            raise ValueError("trusted directory provider required")
        # This is a check, never runtime DDL. Dedicated connection is not shared
        # across requests or worker threads and must not automatically reconnect.
        SchemaRunner(connection).require_current()
        self.actor = actor_user_id
        self.state = NativeSubjectState(connection, native_schema=native_schema,
                                       identity_schema=identity_schema, provider=provider_id)
        writer = EventWriter()
        def audit(cursor, event):
            if event["actor"] != self.actor:
                raise ContractError("SUBJECT_UNAVAILABLE", "Subject actor does not match", 503)
            writer.append(cursor, dict(event_id=str(uuid4()),
                occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                request_id=request_id, actor_user_id=self.actor, actor_kind="user",
                source="directory", action="subject.memberships", result="succeeded",
                subject_revision=event["epoch"]))
        self.projector = NativeMembershipProjector(connection, native_schema=native_schema,
            identity_schema=identity_schema, provider=provider_id,
            assert_generation=lambda user, epoch: self.contexts.assert_generation(user, epoch),
            audit_hook=audit, attribute_allowlist=directory.attribute_allowlist)
        self.contexts = SubjectContexts(redis, provider_id=provider_id, fetch=directory.fetch,
            attribute_allowlist=directory.attribute_allowlist,
            account_active=self.state.account_active, barrier_active=self.state.barrier_active,
            refresh_guard=self.state.refresh_guard,
            project=lambda subject, epoch: self.projector.apply(subject, epoch,
                native_username=self.state.username(subject["userId"])), prefix=prefix)

    def prepare(self, user_id, *, trigger="request"):
        identifier(user_id, maximum=225)
        if user_id != self.actor:
            raise ContractError("ACCESS_DENIED", "Only the authenticated subject may be prepared", 403)
        return self.contexts.get(user_id, trigger=trigger)
