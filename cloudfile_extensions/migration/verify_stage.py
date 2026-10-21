"""Verify actual completed stage evidence through a fenced library job."""
import os
import time
from uuid import UUID, uuid5

from ..common.errors import ContractError
from ..common.validation import object_fields
from ..jobs.store import JobStore
from ..jobs.worker import Execution, JobResult
from .verify_copy import WorkingCopyVerifier
from .working_copy import ImportWorkingCopy
from .workspace_guard import ImportWorkspaceGuard


class ImportVerifyStage:
    def __init__(self, *, verifier, clock=time.monotonic):
        if not isinstance(verifier, WorkingCopyVerifier) or not callable(clock):
            raise ValueError("actual registered copy verifier required")
        self.verifier, self.clock = verifier, clock

    def __call__(self, execution):
        if not isinstance(execution, Execution) or not isinstance(execution.store, JobStore):
            raise ValueError("actual owned SQL job execution required")
        claim = execution.claim
        object_fields(claim.request, ("stage_job_id",))
        stage_id = claim.request["stage_job_id"]
        if (not isinstance(stage_id, str) or str(UUID(stage_id)) != stage_id or
                claim.kind != "migration.verify-copy" or claim.scope.get("type") != "repo"):
            raise ContractError("INVALID_REQUEST", "Exact library stage verification required", 400)
        stage = execution.store.get(stage_id)
        current = execution.store.get(claim.job_id)
        if (stage["kind"] != "migration.stage" or stage["status"] != "succeeded" or stage["step"] != "finished" or
                stage["scope"] != claim.scope or (stage["actor"], stage["actor_kind"]) != (current["actor"], current["actor_kind"]) or
                type(stage["lease_epoch"]) is not int or stage["lease_epoch"] < 1):
            raise ContractError("IMPORT_STAGE_UNAVAILABLE", "Matching successful staging evidence required", 409)
        saved = stage["checkpoint"]
        object_fields(saved, ("workspace_ref", "source_id", "files", "directories", "bytes", "manifest_sha256",
            "source_snapshot_verified", "import_verified"))
        attempt = str(uuid5(UUID(stage_id), "cloudfile.import.stage.v1:" + str(stage["lease_epoch"])))
        if (saved["workspace_ref"] != "import-work:" + attempt or stage["result_ref"] != saved["workspace_ref"] or
                saved["source_snapshot_verified"] is not False or saved["import_verified"] is not False):
            raise ContractError("IMPORT_STAGE_UNAVAILABLE", "Saved staging evidence changed", 409)
        copy = ImportWorkingCopy(saved["workspace_ref"], os.path.join(self.verifier.work_root, attempt, "data"),
            saved["manifest_sha256"], saved["files"], saved["directories"], saved["bytes"])
        base = dict(stage_job_id=stage_id, stage_epoch=stage["lease_epoch"], workspace_ref=copy.workspace_ref,
            import_verified=False)
        execution.checkpoint(step="copy-verifying", value=base)
        last = self.clock()
        def checkpoint(counts):
            nonlocal last
            now = self.clock()
            if now - last >= min(10, execution.lease_seconds / 3):
                execution.checkpoint(step="copy-verifying", value=dict(base, **counts))
                last = now
            return False
        with ImportWorkspaceGuard(work_root=self.verifier.work_root).scope(copy.workspace_ref) as assert_current:
            observed = self.verifier.verify(copy, checkpoint=checkpoint)
            # Re-read evidence after filesystem waits while coordination remains
            # held. This observation still does not authorize future native sync.
            if execution.store.get(stage_id) != stage:
                raise ContractError("IMPORT_STAGE_UNAVAILABLE", "Staging evidence changed during verification", 409)
            assert_current()
            execution.checkpoint(step="copy-verified", value=dict(observed, stage_job_id=stage_id,
                stage_epoch=stage["lease_epoch"]))
        return JobResult(copy.workspace_ref)
