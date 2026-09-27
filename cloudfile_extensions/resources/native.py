"""Bounded CE14 path-birth evidence for the currently open Web workflows.

No UID allocator, lifecycle journal or structural-operation framework. Rename,
copy and restore remain closed; truncated or merged history is not inferred.
"""
import re
import time

from ..common.errors import ContractError
from .paths import resource_ref
from .store import ResourceEvidence


class NativeResourceReader:
    def __init__(self, api, *, max_commits=256, seconds=2):
        if type(max_commits) is not int or not 1 <= max_commits <= 4096 or not 0 < seconds <= 10:
            raise ValueError("bounded native history budget required")
        self.api, self.max_commits, self.seconds = api, max_commits, seconds

    @staticmethod
    def pending():
        raise ContractError("PATH_STATE_PENDING", "Native resource history is unavailable", 503)

    @staticmethod
    def commit_id(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None

    def __call__(self, cursor, reference):
        ref = resource_ref(reference)
        deadline = time.monotonic() + self.seconds
        try:
            # All CE publications update this row. Hold it through the enclosing
            # metadata transaction; RPC reads use immutable commits, not live head.
            cursor.execute("SELECT commit_id FROM Branch WHERE repo_id=%s AND name='master' FOR UPDATE",
                (ref["repo_id"],))
            rows = cursor.fetchall()
            if len(rows) != 1 or not self.commit_id(rows[0][0]):
                self.pending()
            repo = self.api.get_repo(ref["repo_id"])
            if repo is None or type(repo.version) is not int:
                self.pending()
            lookup = (self.api.get_file_id_by_commit_and_path if ref["kind"] == "file"
                else self.api.get_dir_id_by_commit_and_path)
            current, birth, seen = rows[0][0], None, set()
            for _ in range(self.max_commits):
                if time.monotonic() >= deadline or current in seen:
                    self.pending()
                seen.add(current)
                commit = self.api.get_commit(ref["repo_id"], repo.version, current)
                if (commit is None or commit.id != current
                        or getattr(commit, "second_parent_id", None)):
                    self.pending()
                object_id = lookup(ref["repo_id"], current, ref["path"])
                if object_id is None:
                    if birth is None:
                        raise ContractError("RESOURCE_NOT_FOUND", "Resource does not exist", 404)
                    break
                if not self.commit_id(object_id):
                    self.pending()
                birth = current
                parent = commit.parent_id
                if not parent:
                    break
                if not self.commit_id(parent):
                    self.pending()
                current = parent
            else:
                self.pending()
            if time.monotonic() >= deadline:
                self.pending()
            # This is the observed creation boundary, not the latest content hash
            # or head. Replacing bytes retains it; deletion/recreation changes it.
            return ResourceEvidence("ce14:path-birth:" + birth)
        except ContractError:
            raise
        except Exception:
            self.pending()
