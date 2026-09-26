"""Native administrator single-user refresh submission; no public auth adapter."""
from ..authorization.runtime import AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from ..jobs.authority import scope_locks
from ..jobs.store import JobStore
from ..schema.runner import SchemaRunner
from .native_state import NativeSubjectState
from .refresh_worker import UserRefreshJob
from uuid import UUID
import re


class UserRefreshManagement:
    def __init__(self, connection, *, actor, provider, native_schema, identity_schema):
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ValueError("actually authenticated native administrator required")
        SchemaRunner(connection).require_current()
        self.actor = actor
        self.state = NativeSubjectState(connection, native_schema=native_schema,
            identity_schema=identity_schema, provider=provider)
        self.jobs = JobStore(connection)

    def _authorize(self, cursor, target):
        for schema, table in ((self.state.native_schema, "EmailUser"),
                              (self.state.identity_schema, "profile_profile")):
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s",
                (schema, table))
            if cursor.fetchall() != (("InnoDB",),):
                raise ContractError("SUBJECT_UNAVAILABLE", "Refresh identity storage is unavailable", 503)
        manager = self.state.username(self.actor.user_id)
        if manager != self.actor.native_username:
            return False
        cursor.execute("SELECT email,is_active,is_staff FROM " + self.state.accounts + " WHERE email=%s FOR UPDATE", (manager,))
        if cursor.fetchall() != ((manager, 1, 1),):
            return False
        for user in sorted({self.actor.user_id, target}):
            username = self.state.username(user)
            cursor.execute("SELECT user,login_id FROM " + self.state.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE",
                (username, user))
            if cursor.fetchall() != ((username, user),):
                return False
            cursor.execute("SELECT email,is_active FROM " + self.state.accounts + " WHERE email=%s FOR UPDATE", (username,))
            if cursor.fetchall() != ((username, 1),):
                return False
            if self.state.barrier_active(self.state.provider, user):
                raise ContractError("SUBJECT_UNAVAILABLE", "Refresh scope is fenced", 503)
        return True

    def submit(self, request, *, idempotency_key):
        object_fields(request, ("scope", "refresh_subject", "reason"))
        scope = request["scope"]
        object_fields(scope, ("type", "provider", "external_id"))
        target = identifier(scope["external_id"], maximum=225)
        if (scope["type"] != "user" or scope["provider"] != self.state.provider
                or request["refresh_subject"] is not True):
            raise ContractError("INVALID_REQUEST", "Only single-user subject refresh is supported", 400)
        reason = request["reason"]
        if (not isinstance(reason, str) or not reason.strip() or len(reason) > 512
                or any(ord(char) < 32 for char in reason)):
            raise ContractError("INVALID_REQUEST", "Invalid refresh reason", 400)
        scopes = [dict(type="provider", provider=self.state.provider, external_id=self.state.provider)]
        scopes.extend(dict(type="user", provider=self.state.provider, external_id=user)
            for user in sorted({self.actor.user_id, target}))
        with scope_locks(self.jobs.connection, scopes):
            return self.jobs.submit(actor=self.actor.user_id, actor_kind="user", kind=UserRefreshJob.KIND,
                scope=scope, request=dict(userId=target, reason=reason), idempotency_key=idempotency_key,
                authorize_transaction=lambda cursor: self._authorize(cursor, target))

    @staticmethod
    def public_job(job):
        steps = {"accepted": "accepted", "processing": "fetching",
                 "subject_refreshed": "reconciling", "finished": "finished"}
        if job["status"] not in {"queued", "running", "succeeded", "failed", "cancelled"} or job["step"] not in steps:
            raise ContractError("SUBJECT_UNAVAILABLE", "Refresh job state is unavailable", 503)
        code = job["error_code"]
        if code is not None and (not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code)):
            raise ContractError("SUBJECT_UNAVAILABLE", "Refresh job state is unavailable", 503)
        return dict(job_id=job["job_id"], status=job["status"], step=steps[job["step"]],
            scope=dict(job["scope"]), barrier_active=job["barrier_active"],
            status_url="/api/v2.1/cloudfile/extensions/authorization/v1/refreshes/" + job["job_id"] + "/",
            error_code=code)

    def status(self, job_id):
        try:
            job_id = str(UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            raise ContractError("INVALID_REQUEST", "Invalid refresh job identity", 400) from None
        previous = self.jobs.get(job_id)
        scope = previous["scope"]
        if (previous["kind"] != UserRefreshJob.KIND or previous["actor_kind"] != "user"
                or set(scope) != {"type", "provider", "external_id"}
                or scope["type"] != "user" or scope["provider"] != self.state.provider
                or previous["barrier_active"]):
            raise ContractError("NOT_FOUND", "Refresh job is not available", 404)
        target = identifier(scope["external_id"], maximum=225)
        scopes = [dict(type="provider", provider=self.state.provider, external_id=self.state.provider)]
        scopes.extend(dict(type="user", provider=self.state.provider, external_id=user)
            for user in sorted({self.actor.user_id, target}))
        connection = self.jobs.connection
        with scope_locks(connection, scopes):
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    if self._authorize(cursor, target) is not True:
                        raise ContractError("ACCESS_DENIED", "Refresh status is not authorized", 403)
                    cursor.execute("SELECT job_id FROM cf_background_job WHERE job_id=%s FOR UPDATE", (job_id,))
                    if cursor.fetchall() != ((job_id,),):
                        raise ContractError("NOT_FOUND", "Refresh job is not available", 404)
                    current = self.jobs.get(job_id)
                    if (current["scope"] != scope or current["kind"] != UserRefreshJob.KIND
                            or current["actor_kind"] != "user" or current["barrier_active"]):
                        raise ContractError("SUBJECT_UNAVAILABLE", "Refresh scope changed", 503)
                    result = self.public_job(current)
                connection.commit()
                return result
            finally:
                connection.rollback()
