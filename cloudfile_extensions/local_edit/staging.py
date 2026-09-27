"""Measured, unlink-before-handoff upload bytes; no identity/file write grant.

The eventual upload endpoint must authenticate before receiving bytes and own
its transport deadline. This blocking stream adapter does not invent a timeout
or accept a client path. It neither publishes content nor persists an intent.
"""
import hashlib
import os
import secrets
import stat


class StageUnavailable(Exception):
    def __init__(self):
        super().__init__("Measured upload staging is unavailable")


class MeasuredStage:
    def __init__(self, fd, length, digest):
        self._fd, self.length, self.sha256 = fd, length, digest
        self._pid = os.getpid()

    def __repr__(self):
        return "MeasuredStage(content and descriptor omitted)"

    def take_fd(self):
        """Exactly one native consumer takes ownership of a read-only FD.

        The consumer must independently authorize/measure native staging. A
        descriptor and this local digest are not an object ID or commit grant.
        """
        if self._pid != os.getpid() or self._fd is None:
            raise StageUnavailable()
        value, self._fd = self._fd, None
        return value

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class UploadStaging:
    def __init__(self, configured_directory, *, maximum_bytes):
        if (os.name != "posix" or not isinstance(configured_directory, str) or
                not os.path.isabs(configured_directory) or
                os.path.normpath(configured_directory) != configured_directory or
                type(maximum_bytes) is not int or not 0 <= maximum_bytes <= 2 ** 63 - 1):
            raise ValueError("Private configured POSIX staging directory and byte budget required")
        self.maximum_bytes = maximum_bytes
        self._pid = os.getpid()
        self._directory = None
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for component in configured_directory.split("/")[1:]:
                if not component or component in {".", ".."}:
                    raise StageUnavailable()
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory)
                os.close(directory)
                directory = child
                info = os.fstat(directory)
                # Root-owned sticky temporary parents are acceptable; the final
                # directory itself must still be private and service-owned.
                if info.st_uid not in {0, os.geteuid()} or (
                        info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                    raise StageUnavailable()
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise StageUnavailable()
            self._directory, directory = directory, None
        except (OSError, StageUnavailable):
            raise StageUnavailable() from None
        finally:
            if directory is not None:
                os.close(directory)

    def receive(self, stream, *, content_length):
        if (self._directory is None or self._pid != os.getpid() or
                type(content_length) is not int or not 0 <= content_length <= self.maximum_bytes):
            raise StageUnavailable()
        name = secrets.token_hex(16) + ".stage"
        writable = readonly = None
        created = False
        try:
            writable = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=self._directory)
            created = True
            digest = hashlib.sha256()
            received = 0
            while received < content_length:
                budget = min(65536, content_length - received)
                data = stream.read(budget)
                if type(data) is not bytes or not 0 < len(data) <= budget:
                    raise StageUnavailable()
                remaining = memoryview(data)
                while remaining:
                    count = os.write(writable, remaining)
                    if count <= 0:
                        raise StageUnavailable()
                    remaining = remaining[count:]
                digest.update(data)
                received += len(data)
            # The HTTP adapter must expose a bounded body stream so this EOF
            # check cannot consume a subsequent request or block indefinitely.
            if stream.read(1) != b"":
                raise StageUnavailable()
            os.fsync(writable)
            os.fchmod(writable, 0o400)
            before = os.fstat(writable)
            readonly = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._directory)
            after = os.fstat(readonly)
            if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1 or after.st_uid != os.geteuid() or
                    stat.S_IMODE(after.st_mode) != 0o400 or after.st_size != received or
                    (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)):
                raise StageUnavailable()
            os.close(writable)
            writable = None
            os.unlink(name, dir_fd=self._directory)
            created = False
            if os.fstat(readonly).st_nlink != 0:
                raise StageUnavailable()
            result = MeasuredStage(readonly, received, digest.hexdigest())
            readonly = None
            return result
        except (OSError, TypeError, ValueError, StageUnavailable):
            raise StageUnavailable() from None
        finally:
            if writable is not None:
                os.close(writable)
            if readonly is not None:
                os.close(readonly)
            if created:
                try:
                    os.unlink(name, dir_fd=self._directory)
                except FileNotFoundError:
                    pass

    def close(self):
        if self._directory is not None:
            os.close(self._directory)
            self._directory = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
