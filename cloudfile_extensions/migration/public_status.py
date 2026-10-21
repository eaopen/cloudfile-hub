"""Allowlisted preparation progress; never serialize private job checkpoints."""
import re

from ..common.errors import ContractError


def public_status(job):
    try:
        operations = {"migration.scan": "scan", "migration.stage": "stage", "migration.verify-copy": "verify-copy"}
        operation = operations[job["kind"]]
        status, step, epoch, attempts = (job[name] for name in ("status", "step", "lease_epoch", "attempts"))
        if (status not in {"queued", "running", "succeeded", "failed", "cancelled"} or
                not isinstance(step, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", step) or
                type(epoch) is not int or not 0 <= epoch <= 2 ** 64 - 1 or
                type(attempts) is not int or not 0 <= attempts <= 2 ** 32 - 1):
            raise ValueError()
        error = job["error_code"]
        if error is not None and (not isinstance(error, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", error)):
            raise ValueError()
        checkpoint = job["checkpoint"] or {}
        if not isinstance(checkpoint, dict) or checkpoint.get("import_verified", False) is not False:
            raise ValueError()
        progress = {}
        for key in ("files", "directories", "bytes", "errors"):
            if key in checkpoint:
                value = checkpoint[key]
                if type(value) is not int or not 0 <= value <= 2 ** 64 - 1:
                    raise ValueError()
                progress[key] = str(value)
        return dict(job_id=job["job_id"], operation=operation, status=status, step=step, attempts=attempts,
            lease_epoch=str(epoch), error_code=error, progress=progress,
            copy_verified=operation == "verify-copy" and status == "succeeded" and checkpoint.get("copy_verified") is True,
            import_verified=False)
    except (KeyError, ValueError, TypeError):
        raise ContractError("MIGRATION_UNAVAILABLE", "Migration status requires reconciliation", 503) from None
