"""Local working-volume coordination, not distributed HA or authorization."""
from contextlib import contextmanager
import fcntl
import os
import stat
from uuid import UUID

from ..common.errors import ContractError


class ImportWorkspaceGuard:
    def __init__(self, *, work_root):
        if not isinstance(work_root, str) or not os.path.isabs(work_root):
            raise ValueError("registered local working volume required")
        self.work_root = work_root

    @contextmanager
    def scope(self, workspace_ref):
        if not isinstance(workspace_ref, str) or not workspace_ref.startswith("import-work:"):
            raise ValueError("canonical internal workspace reference required")
        attempt = workspace_ref[len("import-work:"):]
        if str(UUID(attempt)) != attempt:
            raise ValueError("canonical internal workspace reference required")
        descriptors = []
        try:
            root = os.open(self.work_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(root)
            workspace = os.open(attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            descriptors.append(workspace)
            lock = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=workspace)
            descriptors.append(lock)
            observed = os.fstat(lock)
            directory = os.fstat(workspace)
            if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or
                    observed.st_uid != os.geteuid() or observed.st_mode & 0o077):
                raise ContractError("IMPORT_WORKSPACE_UNAVAILABLE", "Private workspace lock required", 503)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ContractError("IMPORT_WORKSPACE_BUSY", "Working copy is already in use", 409) from None

            def assert_current():
                current = os.stat(".lock", dir_fd=workspace, follow_symlinks=False)
                current_directory = os.stat(attempt, dir_fd=root, follow_symlinks=False)
                if ((current.st_dev, current.st_ino, current.st_nlink) != (observed.st_dev, observed.st_ino, 1) or
                        (current_directory.st_dev, current_directory.st_ino) != (directory.st_dev, directory.st_ino)):
                    raise ContractError("IMPORT_WORKSPACE_CHANGED", "Working-copy coordination changed", 409)
            assert_current()
            yield assert_current
            assert_current()
        except ContractError:
            raise
        except OSError:
            raise ContractError("IMPORT_WORKSPACE_UNAVAILABLE", "Working-copy coordination is unavailable", 503) from None
        finally:
            # Closing the descriptor releases flock on process exit/crash too.
            # The inode is retained: deleting/recreating a lock permits split locks.
            for descriptor in reversed(descriptors):
                os.close(descriptor)
