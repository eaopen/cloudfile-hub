"""Read-only bounded seaf-cli status; observations never prove import completion."""
import json
import math
import os
import selectors
import subprocess
import time
from uuid import UUID

from ..common.errors import ContractError


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate status key")
        result[key] = value
    return result


def decode_status(raw, repo_id):
    """Normalize only the selected library; do not expose native diagnostics."""
    try:
        if str(UUID(repo_id)) != repo_id or not isinstance(raw, bytes) or len(raw) > 1048576:
            raise ValueError()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict) or set(value) != {"repos", "sync_errors"}:
            raise ValueError()
        repos, errors = value["repos"], value["sync_errors"]
        if not isinstance(repos, list) or len(repos) > 100 or not isinstance(errors, list) or len(errors) > 100:
            raise ValueError()
        if any(not isinstance(row, dict) for row in repos + errors):
            raise ValueError()
        selected = [row for row in repos if row.get("id") == repo_id]
        if len(selected) != 1:
            raise ValueError()
        row = selected[0]
        state = row.get("state")
        if not isinstance(state, str) or not state or len(state) > 64 or not all(32 <= ord(c) < 127 for c in state):
            raise ValueError()
        progress = row.get("progress")
        if progress is not None and (type(progress) not in (int, float) or not math.isfinite(progress) or not 0 <= progress <= 100):
            raise ValueError()
        return dict(repo_id=repo_id, native_state=state, progress=progress,
            recent_error_count=sum(row.get("repo_id") == repo_id for row in errors),
            import_verified=False)
    except (ValueError, TypeError, UnicodeError, AttributeError):
        raise ContractError("IMPORT_STATUS_UNAVAILABLE", "Native import status is unavailable", 503) from None


class NativeImportStatus:
    def __init__(self, *, executable, confdir):
        if any(not isinstance(value, str) or not os.path.isabs(value) or "\0" in value
               for value in (executable, confdir)):
            raise ValueError("fixed deployment executable and isolated config directory required")
        self.executable, self.confdir = executable, confdir

    def observe(self, repo_id):
        if not isinstance(repo_id, str) or str(UUID(repo_id)) != repo_id:
            raise ValueError("canonical target library required")
        process = None
        try:
            # No shell, caller arguments, credentials, ambient environment or
            # raw stdout/stderr in logs. This command never starts/syncs/imports.
            process = subprocess.Popen([self.executable, "status", "-c", self.confdir,
                "--json", "--sync-error-count", "100"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"})
            deadline = time.monotonic() + 10
            chunks, size = [], 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ValueError()
                    chunk = os.read(process.stdout.fileno(), min(65536, 1048577 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 1048576:
                        raise ValueError()
                    chunks.append(chunk)
            if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                raise ValueError()
            return decode_status(b"".join(chunks), repo_id)
        except Exception:
            raise ContractError("IMPORT_STATUS_UNAVAILABLE", "Native import status is unavailable", 503) from None
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                process.stdout.close()
