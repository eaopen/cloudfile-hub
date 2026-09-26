"""Streaming working-copy integrity observation; not a future sync grant."""
import hashlib
import json
import os
import re
import stat
from uuid import UUID

from ..common.errors import ContractError
from .native_status import _object
from .working_copy import ImportWorkingCopy


class WorkingCopyVerifier:
    def __init__(self, *, work_root):
        if not isinstance(work_root, str) or not os.path.isabs(work_root):
            raise ValueError("registered working volume required")
        self.work_root = work_root

    def verify(self, copy, *, checkpoint):
        if not isinstance(copy, ImportWorkingCopy) or not callable(checkpoint):
            raise ValueError("trusted saved staging evidence and lease callback required")
        attempt = copy.workspace_ref.removeprefix("import-work:")
        if (copy.workspace_ref != "import-work:" + str(UUID(attempt)) or
                not re.fullmatch(r"[0-9a-f]{64}", copy.manifest_sha256) or
                any(type(value) is not int or value < 0 for value in (copy.files, copy.directories, copy.bytes))):
            raise ValueError("canonical saved staging evidence required")
        descriptors = []
        try:
            volume = os.open(self.work_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(volume)
            workspace = os.open(attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=volume)
            descriptors.append(workspace)
            data = os.open("data", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=workspace)
            descriptors.append(data)
            manifest = os.open("manifest.ndjson", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=workspace)
            descriptors.append(manifest)
            before = os.fstat(manifest)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError()
            counts = dict(files=0, directories=0, bytes=0)
            digest = hashlib.sha256()

            def heartbeat():
                if checkpoint(dict(counts)) is True:
                    raise ContractError("IMPORT_CANCELLED", "Working-copy verification cancelled", 409)

            # The digest authenticates the manifest against actual stage
            # checkpoint evidence, never a browser's expected digest. Original
            # builder emits each filesystem path once; no million-entry set.
            with os.fdopen(os.dup(manifest), "rb") as stream:
                while raw := stream.readline(16385):
                    heartbeat()
                    if len(raw) > 16384 or not raw.endswith(b"\n"):
                        raise ValueError()
                    digest.update(raw)
                    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
                    if not isinstance(value, dict):
                        raise ValueError()
                    kind, path = value.get("kind"), value.get("path")
                    if kind not in ("file", "directory") or not isinstance(path, str):
                        raise ValueError()
                    if len(path.encode("utf-8")) + 1 > 4096:
                        raise ValueError()
                    parts = path.split("/")
                    if len(parts) > 129 or any(part in ("", ".", "..") or "\0" in part for part in parts):
                        raise ValueError()
                    parent = os.dup(data)
                    try:
                        for part in parts[:-1]:
                            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                            os.close(parent)
                            parent = child
                        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                        if kind == "directory":
                            flags |= os.O_DIRECTORY
                        item = os.open(parts[-1], flags, dir_fd=parent)
                        try:
                            observed = os.fstat(item)
                            if kind == "directory":
                                if set(value) != {"kind", "path"}:
                                    raise ValueError()
                                counts["directories"] += 1
                            else:
                                if (set(value) != {"kind", "path", "size", "sha256"} or not stat.S_ISREG(observed.st_mode) or
                                        type(value["size"]) is not int or value["size"] < 0 or observed.st_size != value["size"] or
                                        not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])):
                                    raise ValueError()
                                content, size = hashlib.sha256(), 0
                                while chunk := os.read(item, 1024 * 1024):
                                    heartbeat()
                                    content.update(chunk)
                                    size += len(chunk)
                                after = os.fstat(item)
                                if (content.hexdigest() != value["sha256"] or size != value["size"] or
                                        (observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns) !=
                                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                                    raise ValueError()
                                counts["files"] += 1
                                counts["bytes"] += size
                        finally:
                            os.close(item)
                    finally:
                        os.close(parent)
            after = os.fstat(manifest)
            if (digest.hexdigest() != copy.manifest_sha256 or
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                    counts != dict(files=copy.files, directories=copy.directories, bytes=copy.bytes)):
                raise ValueError()

            actual = dict(files=0, directories=0)
            def inventory(directory, depth):
                if depth > 128:
                    raise ValueError()
                with os.scandir(directory) as entries:
                    for entry in entries:
                        heartbeat()
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISDIR(mode):
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                            try:
                                actual["directories"] += 1
                                inventory(child, depth + 1)
                            finally:
                                os.close(child)
                        elif stat.S_ISREG(mode):
                            actual["files"] += 1
                        else:
                            raise ValueError()
            inventory(data, 0)
            if actual != dict(files=copy.files, directories=copy.directories):
                raise ValueError()
            return dict(workspace_ref=copy.workspace_ref, manifest_sha256=copy.manifest_sha256,
                **counts, copy_verified=True, import_verified=False)
        except ContractError:
            raise
        except (ValueError, TypeError, OSError, UnicodeError):
            raise ContractError("IMPORT_COPY_CHANGED", "Working copy does not match saved staging evidence", 409) from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
