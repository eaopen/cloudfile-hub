"""Durable JIT-to-subject preparation recovery; never creates a login session."""
import hashlib
import json
from contextlib import contextmanager

from ..common.errors import ContractError
from ..common.validation import object_fields
from ..directory.preparation import SubjectPreparation
from ..jobs.store import JobStore, canonical
from ..jobs.worker import Handler, JobResult
from .bindings import IdentityBindings
from .jit import SQLJITProvisioner


class ProvisioningJobs:
    KIND = "identity.provision"

    def __init__(self, store, jit, *, preparation_factory):
        if (not isinstance(store, JobStore) or not isinstance(jit, SQLJITProvisioner) or
                store.connection is not jit.bindings.connection or not callable(preparation_factory)):
            raise ValueError("same-connection native provisioning assembly required")
        self.store, self.jit, self.factory = store, jit, preparation_factory
        self.handler = Handler(self.execute)

    def submit(self, identity):
        # Trusted callback only: no tokens, userinfo, employee number, email or
        # browser credentials are stored in a recoverable request.
        request = {key: identity[key] for key in ("issuer", "sub", "userId")}
        if request["issuer"] != self.jit.issuer or not self.jit.enabled:
            raise ContractError("ACCESS_DENIED", "Identity provisioning is not enabled", 403)
        IdentityBindings._identity(request["issuer"], request["sub"], request["userId"])
        scope = dict(type="user", provider=self.jit.bindings.provider, external_id=request["userId"])
        key = hashlib.sha256(canonical(request).encode()).hexdigest()
        return self.store.submit(actor=request["userId"], actor_kind="user", kind=self.KIND,
                                 scope=scope, request=request, idempotency_key=key)

    def request_for_login(self, identity, *, unbound):
        """Fresh verified OIDC caller only; never resurrect cancelled work."""
        if type(unbound) is not bool:
            raise ValueError("invalid identity state")
        request = {key: identity[key] for key in ("issuer", "sub", "userId")}
        if request["issuer"] != self.jit.issuer:
            raise ContractError("ACCESS_DENIED", "Identity provisioning source does not match", 403)
        key = hashlib.sha256(canonical(request).encode()).hexdigest()
        with self.store.connection.cursor() as cursor:
            cursor.execute("SELECT job_id FROM cf_background_job WHERE actor=%s AND actor_kind='user' AND kind=%s AND idempotency_key=%s LIMIT 2",
                           (request["userId"], self.KIND, key))
            rows = cursor.fetchall()
        if len(rows) > 1:
            raise ContractError("IDENTITY_UNAVAILABLE", "Provisioning state is ambiguous", 503)
        if not rows:
            if not unbound:
                return None  # Existing prebound account, not a JIT job.
            job_id, _ = self.submit(identity)
        else:
            job_id = rows[0][0]
        job = self.store.get(job_id)
        with self.store.connection.cursor() as cursor:
            cursor.execute("SELECT request_json FROM cf_background_job WHERE job_id=%s", (job_id,))
            stored = cursor.fetchall()
        expected = dict(type="user", provider=self.jit.bindings.provider, external_id=request["userId"])
        if (job["actor"] != request["userId"] or job["actor_kind"] != "user" or
                job["scope"] != expected or len(stored) != 1 or json.loads(stored[0][0]) != request or job["barrier_active"]):
            raise ContractError("IDENTITY_UNAVAILABLE", "Provisioning state does not match", 503)
        if job["status"] == "failed":
            if not self.jit.enabled:
                raise ContractError("ACCESS_DENIED", "Identity provisioning is not enabled", 403)
            job = self.store.retry_failed(job_id, actor=request["userId"], actor_kind="user")
        if job["status"] == "cancelled":
            raise ContractError("PROVISIONING_CANCELLED", "Identity provisioning was cancelled", 409)
        if job["status"] == "succeeded":
            if unbound:
                raise ContractError("IDENTITY_CONFLICT", "Provisioned identity requires management recovery", 409)
            return None
        if not self.jit.enabled:
            raise ContractError("ACCESS_DENIED", "Identity provisioning is not enabled", 403)
        if job["status"] not in {"queued", "running"}:
            raise ContractError("IDENTITY_UNAVAILABLE", "Provisioning state is unavailable", 503)
        return job_id

    def execute(self, execution):
        claim = execution.claim
        object_fields(claim.request, ("issuer", "sub", "userId"))
        user_id = claim.request["userId"]
        expected_scope = dict(type="user", provider=self.jit.bindings.provider, external_id=user_id)
        if claim.kind != self.KIND or claim.scope != expected_scope:
            raise ContractError("INVALID_REQUEST", "Invalid provisioning scope", 400)
        def assert_claim(cursor):
            cursor.execute("SELECT status,lease_owner,lease_epoch,lease_expiry>UTC_TIMESTAMP(6),actor,actor_kind,scope_id,request_json,barrier_active FROM cf_background_job WHERE job_id=%s FOR UPDATE", (claim.job_id,))
            rows = cursor.fetchall()
            if (len(rows) != 1 or rows[0][:6] != ("running", claim.owner, claim.epoch, 1, user_id, "user") or
                    json.loads(rows[0][6]) != expected_scope or json.loads(rows[0][7]) != claim.request or rows[0][8] != 0):
                raise ContractError("WORKER_LEASE_LOST", "Provisioning lease is no longer current", 409)
        with self.store.connection.cursor() as cursor:
            assert_claim(cursor)
        # Reconcile from actual identity, not checkpoint claims of past success.
        self.jit.ensure(claim.request, assert_transaction=assert_claim)
        execution.checkpoint(step="identity_created", value={})
        preparation = self.factory(user_id)
        if (not isinstance(preparation, SubjectPreparation) or preparation.actor != user_id or
                preparation.state.connection is not self.store.connection):
            raise ValueError("same-connection own-subject preparation required")
        original_assertion = preparation.projector.assert_generation
        original_guard = preparation.contexts.refresh_guard
        def generation(user, epoch):
            original_assertion(user, epoch)
            with self.store.connection.cursor() as cursor:
                assert_claim(cursor)
        preparation.projector.assert_generation = generation
        @contextmanager
        def refresh_guard(user, epoch, *, phase):
            with original_guard(user, epoch, phase=phase) as ownership:
                def proof():
                    ownership()
                    with self.store.connection.cursor() as cursor:
                        assert_claim(cursor)
                proof()
                yield proof
        preparation.contexts.refresh_guard = refresh_guard
        try:
            value = preparation.prepare(user_id, trigger="force")
            execution.checkpoint(step="subject_prepared", value={"context_epoch": value["context_epoch"]})
        finally:
            preparation.projector.assert_generation = original_assertion
            preparation.contexts.refresh_guard = original_guard
        return JobResult()
