"""Descriptor-anchored import copies; never sync or write the registered source."""
from dataclasses import dataclass, field
import hashlib
import json
import os
import stat
from uuid import UUID

from ..common.errors import ContractError
from ..common.validation import identifier


@dataclass(frozen=True)
class ImportWorkingCopy:
    workspace_ref: str
    folder: str = field(repr=False)
    manifest_sha256: str
    files: int
    directories: int
    bytes: int
    source_snapshot_verified: bool = False


class WorkingCopyBuilder:
    def __init__(self, *, sources, work_root):
        if not isinstance(sources, dict) or not sources or not isinstance(work_root, str) or not os.path.isabs(work_root):
            raise ValueError("registered sources and separate work volume required")
        for key, value in sources.items():
            identifier(key)
            if not isinstance(value, str) or not os.path.isabs(value):
                raise ValueError("registered absolute source required")
            source, work = os.path.realpath(value), os.path.realpath(work_root)
            if os.path.commonpath((source, work)) in (source, work):
                raise ValueError("source and working volumes must not overlap")
        self.sources, self.work_root = dict(sources), work_root

    def build(self, source_id, *, attempt_id, checkpoint):
        if source_id not in self.sources or not callable(checkpoint) or str(UUID(attempt_id)) != attempt_id:
            raise ValueError("registered source, canonical unique attempt and lease checkpoint required")
        counters = dict(files=0, directories=0, bytes=0)
        digest = hashlib.sha256()
        descriptors = []
        try:
            source = os.open(self.sources[source_id], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(source)
            root = os.open(self.work_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(root)
            # Never reuse an attempt, overwrite a partial copy or remove evidence.
            os.mkdir(attempt_id, mode=0o700, dir_fd=root)
            attempt = os.open(attempt_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            descriptors.append(attempt)
            lock = os.open(".lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=attempt)
            try:
                os.fsync(lock)
            finally:
                os.close(lock)
            os.mkdir("data", mode=0o700, dir_fd=attempt)
            target = os.open("data", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=attempt)
            descriptors.append(target)
            report_fd = os.open("manifest.ndjson", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=attempt)
            with os.fdopen(report_fd, "wb") as report:
                def heartbeat():
                    # Callback must check actual job epoch/cancellation. No
                    # authorization boolean or caller-supplied identity is used.
                    if checkpoint(dict(counters)) is True:
                        raise ContractError("IMPORT_CANCELLED", "Import copy was cancelled", 409)

                def record(value):
                    encoded = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                    report.write(encoded)
                    digest.update(encoded)

                def directory(src, dst, prefix, depth):
                    observed = os.fstat(src)
                    with os.scandir(src) as entries:
                        for entry in entries:
                            heartbeat()
                            name = entry.name
                            name.encode("utf-8")
                            path = prefix + name
                            before = entry.stat(follow_symlinks=False)
                            if stat.S_ISDIR(before.st_mode):
                                if depth >= 128:
                                    raise ContractError("SOURCE_DEPTH_LIMIT", "Import source depth exceeds limit", 409)
                                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=src)
                                try:
                                    if (os.fstat(child).st_dev, os.fstat(child).st_ino) != (before.st_dev, before.st_ino):
                                        raise ContractError("SOURCE_CHANGED", "Import source changed during copy", 409)
                                    os.mkdir(name, mode=0o700, dir_fd=dst)
                                    copy = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dst)
                                    try:
                                        counters["directories"] += 1
                                        record(dict(path=path, kind="directory"))
                                        directory(child, copy, path + "/", depth + 1)
                                    finally:
                                        os.close(copy)
                                finally:
                                    os.close(child)
                            elif stat.S_ISREG(before.st_mode):
                                file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=src)
                                try:
                                    current = os.fstat(file)
                                    if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                                        raise ContractError("SOURCE_CHANGED", "Import source changed during copy", 409)
                                    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dst)
                                    content, size = hashlib.sha256(), 0
                                    with os.fdopen(output, "wb") as destination:
                                        while chunk := os.read(file, 1024 * 1024):
                                            heartbeat()
                                            destination.write(chunk)
                                            content.update(chunk)
                                            size += len(chunk)
                                        destination.flush()
                                        os.fsync(destination.fileno())
                                    after = os.fstat(file)
                                    if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != current.st_size:
                                        raise ContractError("SOURCE_CHANGED", "Import source changed during copy", 409)
                                    counters["files"] += 1
                                    counters["bytes"] += size
                                    record(dict(path=path, kind="file", size=size, sha256=content.hexdigest()))
                                finally:
                                    os.close(file)
                            else:
                                raise ContractError("SOURCE_UNSUPPORTED", "Import source contains links or special files", 409)
                    after = os.fstat(src)
                    if (observed.st_mtime_ns, observed.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                        raise ContractError("SOURCE_CHANGED", "Import source directory changed during copy", 409)
                    os.fsync(dst)

                directory(source, target, "", 0)
                heartbeat()
                report.flush()
                os.fsync(report.fileno())
            os.fsync(attempt)
            os.fsync(root)
            return ImportWorkingCopy("import-work:" + attempt_id,
                os.path.join(self.work_root, attempt_id, "data"), digest.hexdigest(), **counters)
        except ContractError:
            raise
        except (OSError, UnicodeError):
            raise ContractError("SOURCE_COPY_INCOMPLETE", "Import working copy is incomplete; evidence retained", 409) from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
