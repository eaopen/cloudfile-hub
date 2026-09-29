"""Registered-source dry-run handler with per-attempt streaming report artifacts.

Writes only its report volume, never source files or target libraries. Reports
are internal references and require management authorization before downloading.
"""

import hashlib
import json
import os
import time
from uuid import UUID
from datetime import datetime, timezone

from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from ..jobs.worker import JobResult
from .scanner import SourceScanner
from .scan_limits import ScanLimits


class ImportDryRun:
    def __init__(self, *, sources, report_root, clock=time.monotonic, limits=None):
        if not isinstance(sources, dict) or not sources or not callable(clock):
            raise ValueError("registered import sources are required")
        for source_id, root in sources.items():
            identifier(source_id)
            if not isinstance(root, str) or not os.path.isabs(root):
                raise ValueError("source roots must be deployment registered absolute paths")
        if not isinstance(report_root, str) or not os.path.isabs(report_root):
            raise ValueError("registered report volume is required")
        report_path = os.path.realpath(report_root)
        for root in sources.values():
            source_path = os.path.realpath(root)
            # Reports must not mutate a source or recursively enter its manifest;
            # parent symlink aliases cannot disguise overlapping volumes.
            if os.path.commonpath((source_path, report_path)) in {source_path, report_path}:
                raise ValueError("source and report volumes must not overlap")
        self.limits = limits if limits is not None else ScanLimits()
        if not isinstance(self.limits, ScanLimits):
            raise ValueError("invalid import scan limits")
        self.sources = dict(sources)
        self.report_root = report_root
        self.clock = clock

    def __call__(self, execution):
        claim = execution.claim
        object_fields(claim.request, ("source_id",), ("content_hash",))
        source_id = claim.request["source_id"]
        identifier(source_id)
        if source_id not in self.sources or claim.scope["type"] != "repo":
            raise ContractError("INVALID_REQUEST", "Invalid registered import source or scope", 400)
        content_hash = claim.request.get("content_hash", False)
        if type(content_hash) is not bool:
            raise ContractError("INVALID_REQUEST", "Invalid import hash option", 400)
        # Per-attempt name never overwrites another worker's or user's report.
        job_id = str(UUID(claim.job_id))
        if type(claim.epoch) is not int or claim.epoch < 1:
            raise ValueError("invalid import attempt epoch")
        name = job_id + "." + str(claim.epoch) + ".ndjson"
        directory = os.open(self.report_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        started = self.clock()
        created_at = datetime.now(timezone.utc).isoformat()
        report_bytes = 0
        entries = 0
        def budget(additional_bytes=0):
            if self.clock() - started >= self.limits.maximum_seconds:
                raise ContractError("IMPORT_SCAN_TIMEOUT", "Import scan time budget exceeded", 409)
            if report_bytes + additional_bytes > self.limits.maximum_report_bytes:
                raise ContractError("IMPORT_REPORT_LIMIT", "Import report budget exceeded", 409)
            available = os.fstatvfs(directory)
            if available.f_bavail * available.f_frsize < self.limits.minimum_free_bytes + additional_bytes:
                raise ContractError("IMPORT_REPORT_SPACE_LOW", "Import report storage reserve reached", 409)
        try:
            budget()
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            counts = {"files": 0, "directories": 0, "bytes": 0, "errors": 0}
            digest = hashlib.sha256()
            heartbeat_at = self.clock()
            def heartbeat():
                nonlocal heartbeat_at
                budget()
                now = self.clock()
                if now - heartbeat_at >= min(10, execution.lease_seconds / 3):
                    execution.checkpoint(step="scanning", value=dict(counts))
                    heartbeat_at = now
                return False
            try:
                with os.fdopen(descriptor, "wb") as report:
                    for row in SourceScanner(self.sources[source_id], content_hash=content_hash,
                                             cancelled=heartbeat, maximum_depth=self.limits.maximum_depth).scan():
                        entries += 1
                        if entries > self.limits.maximum_entries:
                            raise ContractError("IMPORT_ENTRY_LIMIT", "Import entry budget exceeded", 409)
                        if "error" in row:
                            counts["errors"] += 1
                        elif row["kind"] == "file":
                            counts["files"] += 1
                            counts["bytes"] += row["size"]
                        elif row["kind"] == "directory":
                            counts["directories"] += 1
                        encoded = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                        budget(len(encoded))
                        report.write(encoded)
                        report_bytes += len(encoded)
                        digest.update(encoded)
                    summary = {**counts, "source_id": source_id, "report": "import-report:" + name,
                               "report_sha256": digest.hexdigest(), "source_snapshot_verified": False,
                               "schema_version": 1, "job_id": job_id, "lease_epoch": str(claim.epoch),
                               "created_at": created_at, "report_bytes": report_bytes,
                               "verification_scope": "content_hash" if content_hash else "metadata",
                               "import_verified": False}
                    budget()
                    report.flush()
                    os.fsync(report.fileno())
                os.fsync(directory)
                execution.checkpoint(step="scan-complete", value=summary)
                if counts["errors"]:
                    raise ContractError("SOURCE_SCAN_INCOMPLETE", "Source scan contains reported failures", 409)
                return JobResult(summary["report"])
            except Exception:
                # Preserve partial evidence. Do not delete reports, source files or
                # previously imported content on cancellation, errors or retry.
                raise
        finally:
            os.close(directory)
