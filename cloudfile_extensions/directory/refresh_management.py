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
import time
from ..identity.service_tokens import ServicePrincipal, ServiceTokenVerifier


class UserRefreshManagement:
    def __init__(self, connection, *, actor, provider, native_schema, identity_schema,
                 service_providers=None, service_verifier=None):
        self.machine = isinstance(actor, ServicePrincipal)
        if self.machine:
            if not isinstance(service_verifier, ServiceTokenVerifier) or service_verifier.revocations is None:
                raise ValueError("revocation-aware actual service verifier required")
            if not isinstance(service_providers, frozenset) or provider not in service_providers:
                raise ContractError("ACCESS_DENIED", "Service refresh provider is not allowed", 403)
            actor.require(UserRefreshJob.KIND)
        elif not isinstance(actor, AuthenticatedPolicyActor):
            raise ValueError("actually authenticated native administrator required")
        SchemaRunner(connection).require_current()
        self.actor = actor
        self.service_verifier = service_verifier
        self.actor_id = actor.service_id if self.machine else actor.user_id
        self.actor_kind = "service" if self.machine else "user"
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
        if self.machine:
            self.actor.require(UserRefreshJob.KIND)
            self.service_verifier.assert_active(self.actor)
            if self.actor.expires_at <= time.time():
                raise ContractError("AUTHENTICATION_REQUIRED", "Service refresh credential expired", 401)
        else:
            manager = self.state.username(self.actor.user_id)
            if manager != self.actor.native_username:
                return False
            cursor.execute("SELECT email,is_active,is_staff FROM " + self.state.accounts + " WHERE email=%s FOR UPDATE", (manager,))
            if cursor.fetchall() != ((manager, 1, 1),):
                return False
        for user in self._users(target):
            username = self.state.username(user)
            cursor.execute("SELECT user,login_id FROM " + self.state.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE",
                (username, user))
            if cursor.fetchall() != ((username, user),):
                return False
            cursor.execute("SELECT email,is_active FROM " + self.state.accounts + " WHERE email=%s FOR UPDATE", (username,))
            accounts = cursor.fetchall()
            if (len(accounts) != 1 or accounts[0][0] != username
                    or type(accounts[0][1]) is not int or accounts[0][1] not in (0, 1)):
                return False
            # An inactive target still needs membership removals and diagnostic
            # status. This is not a reactivation grant: the native projector
            # rejects active source projection into an inactive CE account.
            if user != target and accounts[0][1] != 1:
                return False
            if self.state.barrier_active(self.state.provider, user):
                raise ContractError("SUBJECT_UNAVAILABLE", "Refresh scope is fenced", 503)
        return True

    def _users(self, target):
        return [target] if self.machine else sorted({self.actor.user_id, target})

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
            for user in self._users(target))
        with scope_locks(self.jobs.connection, scopes):
            return self.jobs.submit(actor=self.actor_id, actor_kind=self.actor_kind, kind=UserRefreshJob.KIND,
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

    def _job(self, job_id):
        try:
            job_id = str(UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            raise ContractError("INVALID_REQUEST", "Invalid refresh job identity", 400) from None
        previous = self.jobs.get(job_id)
        scope = previous["scope"]
        if (previous["kind"] != UserRefreshJob.KIND or previous["actor_kind"] not in {"user", "service"}
                or set(scope) != {"type", "provider", "external_id"}
                or scope["type"] != "user" or scope["provider"] != self.state.provider
                or previous["barrier_active"]):
            raise ContractError("NOT_FOUND", "Refresh job is not available", 404)
        if self.machine and (previous["actor_kind"] != "service" or previous["actor"] != self.actor_id):
            raise ContractError("NOT_FOUND", "Refresh job is not available", 404)
        return previous

    def status(self, job_id):
        previous = self._job(job_id)
        job_id, scope = previous["job_id"], previous["scope"]
        target = identifier(scope["external_id"], maximum=225)
        scopes = [dict(type="provider", provider=self.state.provider, external_id=self.state.provider)]
        scopes.extend(dict(type="user", provider=self.state.provider, external_id=user)
            for user in self._users(target))
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
                            or current["actor_kind"] != previous["actor_kind"]
                            or current["actor"] != previous["actor"] or current["barrier_active"]):
                        raise ContractError("SUBJECT_UNAVAILABLE", "Refresh scope changed", 503)
                    result = self.public_job(current)
                connection.commit()
                return result
            finally:
                connection.rollback()

    def retry_failed(self, job_id, *, expected_attempt):
        """Internal conditional recovery; never resurrect cancelled work."""
        if type(expected_attempt) is not int or not 0 <= expected_attempt <= 2 ** 63 - 1:
            raise ContractError("INVALID_REQUEST", "Invalid refresh attempt condition", 400)
        previous = self._job(job_id)
        scope, target = previous["scope"], previous["scope"]["external_id"]
        scopes = [dict(type="provider", provider=self.state.provider, external_id=self.state.provider)]
        scopes.extend(dict(type="user", provider=self.state.provider, external_id=user)
            for user in self._users(target))
        def authorize(cursor):
            if self._authorize(cursor, target) is not True:
                return False
            cursor.execute("SELECT lease_epoch,status FROM cf_background_job WHERE job_id=%s FOR UPDATE",
                (previous["job_id"],))
            rows = cursor.fetchall()
            if len(rows) != 1 or rows[0][0] != expected_attempt or rows[0][1] not in {"failed", "queued"}:
                raise ContractError("PRECONDITION_FAILED", "Refresh attempt changed or cannot be retried", 412)
            current = self._job(previous["job_id"])
            if (current["scope"] != scope or current["actor"] != previous["actor"]
                    or current["actor_kind"] != previous["actor_kind"]):
                raise ContractError("SUBJECT_UNAVAILABLE", "Refresh scope changed", 503)
            return True
        with scope_locks(self.jobs.connection, scopes):
            self.jobs.retry_failed(previous["job_id"], actor=self.actor_id, actor_kind=self.actor_kind,
                authorize_transaction=authorize)
        return self.status(previous["job_id"])
