"""One-shot bounded native ticket RPC; no pool, retry or detached thread."""
import json
import socket
import struct
import time


def issue_native_ticket(*arguments):
    from seaserv.service import seafile_pipe_path
    if len(arguments) != 7 or any(not isinstance(value, str) for value in arguments):
        raise ValueError("fixed native ticket arguments required")
    message = json.dumps(dict(service="seafserv-threaded-rpcserver",
        request=json.dumps(["seafile_cloudfile_issue_read_ticket", *arguments],
            ensure_ascii=False, separators=(",", ":"))),
        ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(message) > 131072:
        raise ValueError("native ticket request exceeds budget")
    deadline = time.monotonic() + 5
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
        return response["ret"]
