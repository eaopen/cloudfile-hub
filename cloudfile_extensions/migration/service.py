"""Authenticated library management of implemented preparation jobs only."""
from uuid import UUID

from ..authorization.read import LibraryWideManagementAuthority
from ..common.errors import ContractError
from ..common.validation import identifier, object_fields, sequence
from ..jobs.authority import scope_locks
from ..jobs.store import JobStore
from ..resources.paths import resource_ref
from ..resources.service import ResourceService
from .public_status import public_status


class MigrationJobService:
    operations = {"scan": "migration.scan", "stage": "migration.stage", "verify-copy": "migration.verify-copy"}

    def __init__(self, resources, management, *, source_ids, enabled_operations=frozenset({"scan"})):
        if (not isinstance(resources, ResourceService) or not isinstance(management, LibraryWideManagementAuthority) or
                management.state.connection is not resources.store.connection or management.actor != resources.read_authority.actor or
                not isinstance(source_ids, frozenset) or not 1 <= len(source_ids) <= 64):
            raise ValueError("actual same-connection library management and registered sources required")
        for source in source_ids:
            identifier(source)
        if not isinstance(enabled_operations, frozenset) or not enabled_operations or not enabled_operations <= self.operations.keys():
            raise ValueError("explicit implemented migration operations required")
        self.resources, self.management, self.source_ids = resources, management, source_ids
        self.enabled_operations = enabled_operations
        self.jobs = JobStore(management.state.connection)

    def submit(self, operation, value, *, idempotency_key):
        if operation not in self.enabled_operations:
            raise ContractError("INVALID_REQUEST", "Import operation is unavailable", 400)
        required = ("repo_id", "stage_job_id") if operation == "verify-copy" else ("repo_id", "source_id")
        object_fields(value, required, ("content_hash",) if operation == "scan" else ())
        reference = resource_ref(dict(repo_id=value["repo_id"], path="/", kind="dir"))
        request = {key: item for key, item in value.items() if key != "repo_id"}
        if operation == "verify-copy":
            stage_id = request["stage_job_id"]
            if not isinstance(stage_id, str) or str(UUID(stage_id)) != stage_id:
                raise ContractError("INVALID_REQUEST", "Canonical stage job required", 400)
        else:
            identifier(request["source_id"])
            if request["source_id"] not in self.source_ids or type(request.get("content_hash", False)) is not bool:
                raise ContractError("INVALID_REQUEST", "Registered source and valid scan option required", 400)
        authority = self.management
        authority.preparation.prepare(authority.actor)
        # Order matches native identity/subject/repository effect coordination;
        # JobStore's same-repo nested lock remains on this exact connection.
        with scope_locks(authority.state.connection, authority._scopes(reference)):
            def authorize(sql):
                if authority.authorize(sql, authority.actor, reference) is not True:
                    return False
                if operation == "verify-copy":
                    stage = self.jobs.get(request["stage_job_id"])
                    if (stage["kind"] != "migration.stage" or stage["status"] != "succeeded" or
                            stage["actor"] != authority.actor or stage["actor_kind"] != "user" or
                            stage["scope"] != dict(type="repo", provider="cloudfile", external_id=reference["repo_id"])):
                        raise ContractError("IMPORT_STAGE_UNAVAILABLE", "Matching successful library stage required", 409)
                return True
            job_id, created = self.jobs.submit(actor=authority.actor, actor_kind="user",
                kind=self.operations[operation], scope=dict(type="repo", provider="cloudfile", external_id=reference["repo_id"]),
                request=request, idempotency_key=idempotency_key, barrier=False,
                authorize_transaction=authorize, finalize_transaction=authority.finalize)
        return dict(job_id=job_id, operation=operation, created=created, import_verified=False)

    def _job(self, job_id):
        if not isinstance(job_id, str) or str(UUID(job_id)) != job_id:
            raise ContractError("INVALID_REQUEST", "Canonical migration job required", 400)
        job = self.jobs.get(job_id)
        if (job["kind"] not in self.operations.values() or job["scope"].get("type") != "repo" or
                job["scope"].get("provider") != "cloudfile" or job["actor"] != self.management.actor or job["actor_kind"] != "user"):
            raise ContractError("ACCESS_DENIED", "Migration job is not available", 403)
        return job

    def status(self, value):
        object_fields(value, ("job_id",))
        job_id = value["job_id"]
        job = self._job(job_id)
        reference = dict(repo_id=job["scope"]["external_id"], path="/", kind="dir")
        def read(sql, ref):
            current = self._job(job_id)
            if current["scope"] != job["scope"] or current["kind"] != job["kind"]:
                raise ContractError("JOB_VERSION_CONFLICT", "Migration job changed", 409)
            return public_status(current)
        return self.management.consume(reference, read)

    def transition(self, operation, value):
        if operation not in {"cancel", "retry"}:
            raise ContractError("INVALID_REQUEST", "Migration transition is unavailable", 400)
        object_fields(value, ("job_id", "lease_epoch"))
        epoch = sequence(value["lease_epoch"])
        job = self._job(value["job_id"])
        if operation == "retry" and job["kind"] not in {self.operations[key] for key in self.enabled_operations}:
            raise ContractError("MIGRATION_UNAVAILABLE", "Preparation worker is unavailable", 503)
        authority = self.management
        reference = dict(repo_id=job["scope"]["external_id"], path="/", kind="dir")
        authority.preparation.prepare(authority.actor)
        with scope_locks(authority.state.connection, authority._scopes(reference)):
            def authorize(sql):
                latest = self._job(job["job_id"])
                if latest["scope"] != job["scope"] or latest["kind"] != job["kind"]:
                    raise ContractError("JOB_VERSION_CONFLICT", "Migration job changed", 409)
                return authority.authorize(sql, authority.actor, reference)
            change = self.jobs.cancel if operation == "cancel" else self.jobs.retry_failed
            result = change(job["job_id"], actor=authority.actor, actor_kind="user",
                authorize_transaction=authorize, finalize_transaction=authority.finalize, expected_epoch=epoch)
        return dict(job_id=job["job_id"], status=result["status"], lease_epoch=str(result["lease_epoch"]), import_verified=False)
