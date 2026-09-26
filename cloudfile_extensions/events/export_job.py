"""Trusted audit.export handler; private per-attempt files, no request paths.

Files are not public. Only a succeeded job's exact result reference may later be
served by an independently authorized download adapter. Orphans are not results.
"""

import hashlib
import os
import time
from uuid import UUID, uuid4

from ..common.errors import ContractError
from ..common.validation import object_fields
from ..jobs.worker import JobResult


class AuditExportJob:
    def __init__(self, exporter, *, result_root, clock=time.monotonic):
        if not isinstance(result_root, str) or not os.path.isabs(result_root) or not callable(clock):
            raise ValueError("audit result root must be deployment registered")
        self.exporter, self.root, self.clock = exporter, result_root, clock

    def __call__(self, execution):
        claim = execution.claim
        object_fields(claim.request, ("start", "end"), ("actor_user_id", "action", "result", "path", "resource_uid"))
        if (claim.kind != "audit.export" or claim.scope.get("type") != "repo" or
                claim.scope.get("provider") != "cloudfile" or type(claim.epoch) is not int or claim.epoch < 1):
            raise ContractError("INVALID_REQUEST", "Invalid audit export scope", 400)
        job = execution.store.get(claim.job_id)
        if job["actor_kind"] != "user" or job["barrier_active"]:
            raise ContractError("INVALID_REQUEST", "Audit export requires a user job without a barrier", 400)
        repo = str(UUID(claim.scope["external_id"]))
        name = str(UUID(claim.job_id)) + "." + str(claim.epoch) + ".csv"
        partial = name + "." + uuid4().hex + ".partial"
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        created, published = False, False
        try:
            descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            created = True
            digest, size, heartbeat = hashlib.sha256(), 0, self.clock()
            with os.fdopen(descriptor, "wb") as output:
                for chunk in self.exporter.generate(actor=job["actor"], repo_id=repo, **claim.request):
                    now = self.clock()
                    if now - heartbeat >= min(10, execution.lease_seconds / 3):
                        execution.checkpoint(step="exporting", value={"bytes": size})
                        heartbeat = now
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                output.flush()
                os.fsync(output.fileno())
            # Verify lease after slow I/O, before filesystem publication. This
            # does not make filesystem and SQL atomic: only complete() can make
            # this private file a succeeded job result, fenced by current epoch.
            execution.checkpoint(step="export-generated", value={"bytes": size})
            if self.exporter.authorize(job["actor"], repo) is not True:
                raise ContractError("FORBIDDEN", "Audit export scope is not available", 403)
            os.link(partial, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            published = True
            os.unlink(partial, dir_fd=directory)
            created = False
            os.fsync(directory)
            reference = "audit-export:" + name
            execution.checkpoint(step="export-ready", value={"bytes": size, "sha256": digest.hexdigest(),
                                 "result_ref": reference})
            return JobResult(reference)
        except Exception:
            # Exact names created by this invocation only; never remove another
            # attempt, pre-existing destination, source or unrelated user file.
            if created:
                os.unlink(partial, dir_fd=directory)
            if published:
                os.unlink(name, dir_fd=directory)
            os.fsync(directory)
            raise
        finally:
            os.close(directory)
