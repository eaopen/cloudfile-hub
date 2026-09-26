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
