"""Bounded CE commit directory enumeration for private rebuild workers.

The mandatory native snapshot scope pins the requested commit and guards the
library lifecycle throughout RPCs. This is not a user access grant or a stable
resource UID; incremental lifecycle handling remains a separate requirement.
"""
import re
import stat
from contextlib import contextmanager

from ..common.errors import ContractError
from ..resources.paths import resource_ref


def _native_api():
    from seaserv import seafile_api
    return seafile_api


class NativeCommitDirectoryReader:
    def __init__(self, *, snapshot_scope):
        if not callable(snapshot_scope):
            raise ValueError("actual native commit and library lifecycle scope required")
        self.snapshot_scope = snapshot_scope

    def page(self, *, repo_id, commit_id, path, offset=0, limit=100):
        with self.read_page(repo_id=repo_id, commit_id=commit_id, path=path, offset=offset, limit=limit) as page:
            return page

    @contextmanager
    def read_page(self, *, repo_id, commit_id, path, offset=0, limit=100):
        ref = resource_ref(dict(repo_id=repo_id, path=path, kind="dir"))
        if (not isinstance(commit_id, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_id) or
                type(offset) is not int or not 0 <= offset <= 2 ** 31 - 102 or
                type(limit) is not int or not 1 <= limit <= 100):
            raise ValueError("fixed native commit and bounded directory position required")
        try:
            if len(ref["path"].encode("utf-8")) > 4096:
                raise ValueError()
        except (ValueError, UnicodeError):
            raise ContractError("SEARCH_REBUILD_PENDING", "Invalid rebuild directory", 503) from None
        with self.snapshot_scope(ref["repo_id"], commit_id):
            # CE exposes offset/limit on the commit-specific API. Never invoke
            # unbounded list_dir_by_dir_id or enumerate the current moving head.
            entries = _native_api().list_dir_by_commit_and_path(ref["repo_id"], commit_id, ref["path"], offset, limit + 1)
            if not isinstance(entries, (list, tuple)) or len(entries) > limit + 1:
                raise ContractError("SEARCH_REBUILD_PENDING", "Native snapshot directory is unavailable", 503)
            items, seen = [], set()
            for entry in entries:
                name, mode = getattr(entry, "obj_name", None), getattr(entry, "mode", None)
                if (not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\x00" in name or
                        name in seen or type(mode) is not int or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                    raise ContractError("SEARCH_REBUILD_PENDING", "Native directory entry is invalid", 503)
                seen.add(name)
                child = resource_ref(dict(repo_id=ref["repo_id"], path=("" if ref["path"] == "/" else ref["path"]) + "/" + name,
                    kind="dir" if stat.S_ISDIR(mode) else "file"))
                try:
                    if len(child["path"].encode("utf-8")) > 4096:
                        raise ValueError()
                except (ValueError, UnicodeError):
                    raise ContractError("SEARCH_REBUILD_PENDING", "Native entry path is invalid", 503) from None
                items.append(child)
            yield dict(items=items[:limit], next_offset=offset + limit if len(items) > limit else None)
