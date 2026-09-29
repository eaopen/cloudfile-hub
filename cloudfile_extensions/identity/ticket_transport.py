"""One-shot bounded native ticket RPC; no pool, retry or detached thread."""
import json
import socket
import struct
import time
import re
from uuid import UUID


def _call(function, arguments, deadline):
    from seaserv.service import seafile_pipe_path
    counts = {"seafile_get_repo": 1, "seafile_get_file_id_by_commit_and_path": 3,
        "seafile_cloudfile_issue_read_ticket": 7,
        "seafile_cloudfile_put_file_with_barriers": 6,
        "seafile_cloudfile_publish_edit": 6,
        "seafile_cloudfile_checkin_edit": 4}
    if function not in counts or len(arguments) != counts[function] or any(
            not isinstance(value, str) or "\x00" in value for value in arguments):
        raise ValueError("fixed native ticket arguments required")
    message = json.dumps(dict(service="seafserv-threaded-rpcserver",
        request=json.dumps([function, *arguments],
            ensure_ascii=False, separators=(",", ":"))),
        ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(message) > 131072:
        raise ValueError("native ticket request exceeds budget")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        def budget():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("native ticket RPC deadline")
            connection.settimeout(remaining)

        def receive(length):
            result = bytearray()
            while len(result) < length:
                budget()
                chunk = connection.recv(length - len(result))
                if not chunk:
                    raise ConnectionError("incomplete native ticket response")
                result.extend(chunk)
            return bytes(result)

        budget()
        connection.connect(seafile_pipe_path)
        budget()
        connection.sendall(struct.pack("<I", len(message)) + message)
        size = struct.unpack("<I", receive(4))[0]
        if not 1 <= size <= 1048576:
            raise ValueError("native ticket response exceeds budget")
        def pairs(values):
            result = {}
            for name, value in values:
                if name in result:
                    raise ValueError("duplicate native response field")
                result[name] = value
            return result
        response = json.loads(receive(size).decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(response, dict) or "err_code" in response or "ret" not in response:
            raise ValueError("native ticket response rejected")
        budget()  # Parsing must not turn an expired transport into success.
        return response["ret"]


def resolve_and_issue_native_ticket(repo_id, path, operation, username, conditions, *, expected_object_id=None):
    """All native target I/O shares one absolute five-second budget."""
    if expected_object_id is not None and (not isinstance(expected_object_id, str) or
            not re.fullmatch(r"[0-9a-f]{40}", expected_object_id)):
        raise ValueError("exact expected native object required")
    deadline = time.monotonic() + 5
    repo = _call("seafile_get_repo", (repo_id,), deadline)
    if not isinstance(repo, dict):
        raise ValueError("native repository unavailable")
    # GObject serializers may expose canonical hyphenated property names;
    # reject ambiguous responses rather than choosing between conflicting heads.
    names = [name for name in ("head_cmmt_id", "head-cmmt-id") if name in repo]
    if len(names) != 1:
        raise ValueError("native head unavailable")
    head = repo[names[0]]
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("native head unavailable")
    obj = _call("seafile_get_file_id_by_commit_and_path", (repo_id, head, path), deadline)
    if not isinstance(obj, str) or not re.fullmatch(r"[0-9a-f]{40}", obj):
        raise ValueError("native file unavailable")
    if expected_object_id is not None and obj != expected_object_id:
        raise ValueError("native file changed before ticket issue")
    ticket = _call("seafile_cloudfile_issue_read_ticket",
        (repo_id, path, head, obj, operation, username, conditions), deadline)
    if not isinstance(ticket, str) or len(ticket) != 36 or str(UUID(ticket)) != ticket:
        raise ValueError("native ticket response rejected")
    return ticket
