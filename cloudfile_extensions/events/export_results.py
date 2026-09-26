"""Internal export result verification, never a download authorization grant.

HTTP delivery must additionally hold its native current-authorization guard and
record actual access. A verified filename must not become a public/static URL.
"""

from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import stat
import time
from uuid import UUID

from ..common.errors import ContractError
from ..common.validation import object_fields


@dataclass(frozen=True)
class VerifiedExport:
    job_id: str
    result_ref: str
    size: int
    sha256: str


class AuditExportResults:
    def __init__(self, store, exporter, *, result_root, clock=time.time):
        if not isinstance(result_root, str) or not os.path.isabs(result_root) or not callable(clock):
            raise ValueError("registered audit result root is required")
        self.store, self.exporter, self.root, self.clock = store, exporter, result_root, clock

    def verify(self, job_id, *, actor):
        return self._verify(job_id, actor=actor, include_content=False)

    def read(self, job_id, *, actor):
        """Return verified bounded bytes from the SAME descriptor, not a path."""
        return self._verify(job_id, actor=actor, include_content=True)

    def _verify(self, job_id, *, actor, include_content):
        try:
            job_id = str(UUID(job_id))
        except (ValueError, TypeError, AttributeError):
            raise ContractError("INVALID_REQUEST", "Invalid audit export identity", 400) from None
        job = self.store.get(job_id)
        if job["kind"] != "audit.export" or job["actor_kind"] != "user" or job["actor"] != actor:
            raise ContractError("NOT_FOUND", "Audit export is not available", 404)
        if job["status"] != "succeeded":
            raise ContractError("EXPORT_NOT_READY", "Audit export is not ready", 409)
        metadata = job["checkpoint"]
        name = job_id + "." + str(job["lease_epoch"]) + ".csv"
        reference = "audit-export:" + name
        try:
            if (not isinstance(metadata, dict) or job["result_ref"] != reference or
                    metadata["result_ref"] != reference or type(metadata["bytes"]) is not int or
                    not 0 < metadata["bytes"] <= self.exporter.max_bytes or
                    not isinstance(metadata["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"]) or
                    type(metadata["upper_bound"]) is not int or not 0 <= metadata["upper_bound"] <= 2 ** 63 - 1 or
                    type(metadata["expires_at"]) not in (int, float) or not math.isfinite(metadata["expires_at"]) or
                    not self.clock() < metadata["expires_at"] <= self.clock() + 86400):
                raise ValueError()
            repo = str(UUID(job["scope"]["external_id"]))
            if job["scope"].get("type") != "repo" or job["scope"].get("provider") != "cloudfile":
                raise ValueError()
        except (KeyError, ValueError, TypeError, AttributeError):
            raise ContractError("EXPORT_UNAVAILABLE", "Audit export metadata is unavailable or expired", 409) from None
        if self.exporter.authorize(actor, repo) is not True:
            raise ContractError("FORBIDDEN", "Audit export scope is not available", 403)
        try:
            with self.store.connection.cursor() as sql:
                sql.execute("SELECT request_json FROM cf_background_job WHERE job_id=%s", (job_id,))
                request = json.loads(sql.fetchone()[0])
            object_fields(request, ("start", "end"), ("actor_user_id", "action", "result", "path", "resource_uid"))
        except Exception:
            raise ContractError("EXPORT_UNAVAILABLE", "Audit export request is unavailable", 503) from None
        # Replay current per-row visibility and redaction with the original
        # insertion cutoff. New audit events must not invalidate every export.
        digest, size = hashlib.sha256(), 0
        for chunk in self.exporter.generate(actor=actor, repo_id=repo, upper_bound=metadata["upper_bound"], **request):
            digest.update(chunk)
            size += len(chunk)
        if size != metadata["bytes"] or digest.hexdigest() != metadata["sha256"]:
            raise ContractError("EXPORT_REGENERATE", "Audit visibility changed; create a new export", 409)
        directory, descriptor = None, None
        chunks = []
        try:
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            details = os.fstat(descriptor)
            if (not stat.S_ISREG(details.st_mode) or details.st_size != size or
                    details.st_mode & 0o077 or details.st_nlink != 1):
                raise ValueError()
            actual = hashlib.sha256()
            read_size = 0
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                read_size += len(chunk)
                if read_size > size:
                    raise ValueError()
                actual.update(chunk)
                if include_content:
                    chunks.append(chunk)
            if read_size != size or actual.hexdigest() != digest.hexdigest():
                raise ValueError()
        except (OSError, ValueError):
            raise ContractError("EXPORT_UNAVAILABLE", "Audit export file is unavailable", 503) from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)
        if self.exporter.authorize(actor, repo) is not True:
            raise ContractError("FORBIDDEN", "Audit export scope is not available", 403)
        verified = VerifiedExport(job_id, reference, size, digest.hexdigest())
        return (verified, b"".join(chunks)) if include_content else verified
