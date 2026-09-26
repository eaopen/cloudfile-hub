"""Authenticated library management of implemented preparation jobs only."""
from uuid import UUID

from ..authorization.read import LibraryWideManagementAuthority
from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from ..jobs.authority import scope_locks
from ..jobs.store import JobStore
from ..resources.paths import resource_ref
from ..resources.service import ResourceService


class MigrationJobService:
    operations = {"scan": "migration.scan", "stage": "migration.stage", "verify-copy": "migration.verify-copy"}

    def __init__(self, resources, management, *, source_ids):
        if (not isinstance(resources, ResourceService) or not isinstance(management, LibraryWideManagementAuthority) or
                management.state.connection is not resources.store.connection or management.actor != resources.read_authority.actor or
                not isinstance(source_ids, frozenset) or not 1 <= len(source_ids) <= 64):
            raise ValueError("actual same-connection library management and registered sources required")
        for source in source_ids:
            identifier(source)
        self.resources, self.management, self.source_ids = resources, management, source_ids
        self.jobs = JobStore(management.state.connection)

    def submit(self, operation, value, *, idempotency_key):
        if operation not in self.operations:
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

    def status(self, value):
        object_fields(value, ("job_id",))
        job_id = value["job_id"]
        if not isinstance(job_id, str) or str(UUID(job_id)) != job_id:
            raise ContractError("INVALID_REQUEST", "Canonical migration job required", 400)
        job = self.jobs.get(job_id)
        if (job["kind"] not in self.operations.values() or job["scope"].get("type") != "repo" or
                job["scope"].get("provider") != "cloudfile" or job["actor"] != self.management.actor or job["actor_kind"] != "user"):
            raise ContractError("ACCESS_DENIED", "Migration job is not available", 403)
        reference = dict(repo_id=job["scope"]["external_id"], path="/", kind="dir")
        def read(sql, ref):
            current = self.jobs.get(job_id)
            return dict(job_id=job_id, status=current["status"], step=current["step"],
                attempts=current["attempts"], error_code=current["error_code"], import_verified=False)
        return self.management.consume(reference, read)
