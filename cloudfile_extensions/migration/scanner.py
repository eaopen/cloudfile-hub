"""Read-only streaming source manifests anchored to trusted directory descriptors.

The caller supplies a deployment-registered source root, never a request path.
A scan is evidence, not proof of a consistent source snapshot or completed import.
"""

import hashlib
import os
import stat

from ..common.errors import ContractError


class SourceScanner:
    def __init__(self, root, *, content_hash=False, cancelled=lambda: False, maximum_depth=128):
        if (not isinstance(root, str) or not os.path.isabs(root) or type(content_hash) is not bool
                or not callable(cancelled) or type(maximum_depth) is not int or not 1 <= maximum_depth <= 256):
            raise ValueError("invalid source scan configuration")
        if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY")):
            raise ValueError("source scanning requires a descriptor-safe POSIX runtime")
        self.root = root
        self.content_hash = content_hash
        self.cancelled = cancelled
        self.maximum_depth = maximum_depth

    def scan(self):
        # Keep the original source read-only. Children are opened relative to the
        # retained parent FD so rename/symlink races cannot redirect traversal.
        try:
            root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise ContractError("SOURCE_UNAVAILABLE", "Import source is unavailable", 503) from None
        try:
            yield from self._directory(root, "", 0)
        finally:
            os.close(root)

    def _directory(self, directory, prefix, depth):
        with os.scandir(directory) as entries:
            for entry in entries:
                if self.cancelled():
                    raise ContractError("IMPORT_CANCELLED", "Import scan was cancelled", 409)
                path = prefix + entry.name
                try:
                    path.encode("utf-8", errors="strict")
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        yield {"path": path, "kind": "unsupported", "error": "SOURCE_SYMLINK"}
                    elif stat.S_ISDIR(info.st_mode):
                        if depth >= self.maximum_depth:
                            yield {"path": path, "kind": "directory", "error": "SOURCE_DEPTH_LIMIT"}
                            continue
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                        try:
                            if os.fstat(child).st_ino != info.st_ino or os.fstat(child).st_dev != info.st_dev:
                                yield {"path": path, "kind": "directory", "error": "SOURCE_CHANGED"}
                            else:
                                yield {"path": path, "kind": "directory"}
                                yield from self._directory(child, path + "/", depth + 1)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        yield self._file(directory, entry.name, path, info)
                    else:
                        yield {"path": path, "kind": "unsupported", "error": "SOURCE_SPECIAL_FILE"}
                except UnicodeError:
                    # Never emit invalid Unicode or expose the absolute source root.
                    raise ContractError("SOURCE_NAME_INVALID", "Import source contains an invalid name", 400) from None
                except OSError:
                    yield {"path": path, "kind": "unknown", "error": "SOURCE_UNREADABLE"}

    def _file(self, directory, name, path, observed):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino):
                return {"path": path, "kind": "file", "error": "SOURCE_CHANGED"}
            digest = hashlib.sha256() if self.content_hash else None
            if digest is not None:
                while chunk := os.read(descriptor, 1024 * 1024):
                    if self.cancelled():
                        raise ContractError("IMPORT_CANCELLED", "Import scan was cancelled", 409)
                    digest.update(chunk)
            after = os.fstat(descriptor)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                return {"path": path, "kind": "file", "error": "SOURCE_CHANGED"}
            record = {"path": path, "kind": "file", "size": after.st_size, "mtime_ns": after.st_mtime_ns}
            if digest is not None:
                record["sha256"] = digest.hexdigest()
            return record
        finally:
            os.close(descriptor)
