"""Bounded private audit export garbage collection, explicitly deployment-owned.

No raw audit facts or job rows are deleted. Current running epochs are retained;
only persisted fencing/terminal state or validated expiry proves eligibility.
"""
import math
import os
import re
import stat
import time
from uuid import UUID

from ..jobs.store import JobStore


_NAME = re.compile(r"([0-9a-f-]{36})\.([1-9][0-9]{0,18})\.csv(?:\.[0-9a-f]{32}\.partial)?\Z")


def removable(job, *, job_id, epoch, name, now):
    """Pure eligibility; unknown/corrupt facts never authorize deletion."""
    if (job.get("job_id") != job_id or job.get("kind") != "audit.export"
            or job.get("actor_kind") != "user" or job.get("barrier_active")
            or not isinstance(job.get("scope"), dict)
            or job["scope"].get("type") != "repo"
            or job["scope"].get("provider") != "cloudfile"
            or type(job.get("lease_epoch")) is not int or job["lease_epoch"] < epoch):
        return False
    if job["lease_epoch"] > epoch:
        return True  # old attempt can never become this job's current result
    if job.get("status") in {"failed", "cancelled", "queued"}:
        return True
    if job.get("status") != "succeeded":
        return False  # running, including expired but not reclaimed leases
    checkpoint = job.get("checkpoint")
    reference = "audit-export:" + job_id + "." + str(epoch) + ".csv"
    if name.endswith(".partial"):
        # A succeeded job cannot use any private partial file as its result.
        return job.get("result_ref") == reference
    if not isinstance(checkpoint, dict):
        return False
    expires = checkpoint.get("expires_at")
    return (job.get("result_ref") == reference and checkpoint.get("result_ref") == reference
            and type(expires) in (int, float) and math.isfinite(expires) and 0 < expires <= now)


class AuditExportRetention:
    def __init__(self, store, *, result_root, clock=time.time):
        if (not isinstance(store, JobStore) or not store.connection.get_autocommit()
                or not isinstance(result_root, str) or not os.path.isabs(result_root)
                or not callable(clock)):
            raise ValueError("owned job store and trusted private result root required")
        self.store, self.root, self.clock = store, result_root, clock
        self.directory = self.entries = None

    def close(self):
        if self.entries is not None:
            self.entries.close()
            self.entries = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None

    def run_once(self, *, limit=100):
        """Continue one process-owned scan; inspect at most limit entries.

        A dedicated connection is required, not the job worker's connection or
        an HTTP request's authority transaction. Unknown files remain untouched.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid export cleanup budget")
        counts = dict(inspected=0, removed=0, retained=0, complete=False)
        try:
            if self.directory is None:
                self.directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                if os.fstat(self.directory).st_mode & 0o077:
                    raise ValueError("audit result directory is not private")
                self.entries = os.scandir(self.directory)
            for _ in range(limit):
                try:
                    entry = next(self.entries)
                except StopIteration:
                    counts["complete"] = True
                    if counts["removed"]:
                        os.fsync(self.directory)
                    self.close()
                    break
                counts["inspected"] += 1
                match = _NAME.fullmatch(entry.name)
                try:
                    valid = match is not None and str(UUID(match[1])) == match[1]
                except ValueError:
                    valid = False
                if not valid:
                    counts["retained"] += 1
                    continue
                job_id, epoch = match[1], int(match[2])
                connection = self.store.connection
                connection.begin()
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT job_id FROM cf_background_job WHERE job_id=%s FOR UPDATE", (job_id,))
                        present = cursor.fetchone()
                    eligible = present is not None and removable(self.store.get(job_id),
                        job_id=job_id, epoch=epoch, name=entry.name, now=self.clock())
                    if eligible:
                        try:
                            details = os.stat(entry.name, dir_fd=self.directory, follow_symlinks=False)
                            if (stat.S_ISREG(details.st_mode) and not details.st_mode & 0o077
                                    and details.st_nlink == 1):
                                os.unlink(entry.name, dir_fd=self.directory)
                                counts["removed"] += 1
                            else:
                                counts["retained"] += 1
                        except FileNotFoundError:
                            counts["retained"] += 1
                    else:
                        counts["retained"] += 1
                    connection.commit()
                finally:
                    connection.rollback()
            if counts["removed"] and self.directory is not None:
                os.fsync(self.directory)
            return counts
        except Exception:
            self.close()
            raise
