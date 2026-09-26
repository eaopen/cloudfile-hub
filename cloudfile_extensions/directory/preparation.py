"""Request-scoped own-user subject preparation with real SQL/Redis adapters.

Caller supplies an already authenticated business actor and machine directory
provider. Not an HTTP authentication mechanism or native access permission.
"""
from datetime import datetime, timezone
from contextlib import contextmanager
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
        self._read_epoch = None
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
        if self._read_epoch is not None:
            if trigger != "request":
                raise ContractError("SUBJECT_UNAVAILABLE", "Subject refresh is unavailable inside a read scope", 503)
            value = self.contexts.current(user_id)
            if value is None or value["context_epoch"] != self._read_epoch:
                raise ContractError("SUBJECT_UNAVAILABLE", "Protected read subject changed or expired", 503)
            return value
        return self.contexts.get(user_id, trigger=trigger)

    @contextmanager
    def no_refresh_scope(self):
        """Pin a ready epoch without extending its TTL or granting access.

        Refresh must happen before entering. Nested metadata consumers continue
        native authorization/finalization, but cannot project memberships while
        their producer/authority locks are held. Expiry fails this response;
        the next request can refresh normally. Request-owned, not thread shared.
        """
        value = self.contexts.current(self.actor)
        previous = self._read_epoch
        if value is None or (previous is not None and value["context_epoch"] != previous):
            raise ContractError("SUBJECT_UNAVAILABLE", "Protected read subject is unavailable", 503)
        self._read_epoch = value["context_epoch"]
        try:
            yield
            self.prepare(self.actor)
        finally:
            self._read_epoch = previous

    def refresh_for_management(self, user_id):
        """Trusted leased worker only; disabled success is not login/read ready."""
        identifier(user_id, maximum=225)
        if user_id != self.actor:
            raise ContractError("ACCESS_DENIED", "Only the prepared subject may be refreshed", 403)
        if self._read_epoch is not None:
            raise ContractError("SUBJECT_UNAVAILABLE", "Management refresh cannot run inside a read scope", 503)
        return self.contexts.prepare(user_id, reuse_ready=False, allow_disabled=True)
