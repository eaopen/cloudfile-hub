"""Fenced working-copy stage only; does not start native sync or finish import."""
import time
from uuid import UUID, uuid5

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from ..jobs.worker import Execution, JobResult
from .working_copy import WorkingCopyBuilder


class ImportStage:
    def __init__(self, *, builder, clock=time.monotonic):
        if not isinstance(builder, WorkingCopyBuilder) or not callable(clock):
            raise ValueError("actual registered working-copy builder required")
        self.builder, self.clock = builder, clock

    def __call__(self, execution):
        if not isinstance(execution, Execution):
            raise ValueError("actual leased job execution required")
        claim = execution.claim
        object_fields(claim.request, ("source_id",))
        source_id = claim.request["source_id"]
        identifier(source_id)
        if claim.kind != "migration.stage" or claim.scope.get("type") != "repo" or source_id not in self.builder.sources:
            raise ContractError("INVALID_REQUEST", "Registered library staging job required", 400)
        if type(claim.epoch) is not int or claim.epoch < 1:
            raise ValueError("actual job attempt required")
        attempt = str(uuid5(UUID(claim.job_id), "cloudfile.import.stage.v1:" + str(claim.epoch)))
        # An uncertain/crashed same attempt is not blindly overwritten/reused.
        # A new explicit job retry has a different epoch and isolated workspace.
        execution.checkpoint(step="copy-preparing", value=dict(workspace_ref="import-work:" + attempt,
            source_id=source_id, import_verified=False))
        last = self.clock()
        interval = min(10, execution.lease_seconds / 3)

        def checkpoint(counts):
            nonlocal last
            now = self.clock()
            if now - last >= interval:
                execution.checkpoint(step="copying", value=dict(counts,
                    workspace_ref="import-work:" + attempt, source_id=source_id, import_verified=False))
                last = now
            return False

        copy = self.builder.build(source_id, attempt_id=attempt, checkpoint=checkpoint)
        execution.checkpoint(step="copy-ready", value=dict(workspace_ref=copy.workspace_ref,
            source_id=source_id, files=copy.files, directories=copy.directories, bytes=copy.bytes,
            manifest_sha256=copy.manifest_sha256, source_snapshot_verified=False, import_verified=False))
        return JobResult(copy.workspace_ref)
