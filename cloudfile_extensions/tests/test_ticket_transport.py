"""Real temporary Unix transport fixtures, not native server/ACL evidence."""
from contextlib import contextmanager
import json
import os
import socket
import struct
import tempfile
import threading
import time
from types import ModuleType
import unittest
from unittest.mock import patch

from cloudfile_extensions.identity.ticket_transport import _call


class TicketTransportTests(unittest.TestCase):
    @contextmanager
    def server(self, responder):
        with tempfile.TemporaryDirectory(prefix="cf-rpc-") as directory:
            path = os.path.join(directory, "rpc.sock")
            if len(os.fsencode(path)) > 100:
                self.skipTest("Set TMPDIR to a shorter path for Unix socket fixtures")
            failures, requests = [], []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(2)

                def serve():
                    try:
                        with listener.accept()[0] as connection:
                            connection.settimeout(2)
                            def receive(size):
                                data = bytearray()
                                while len(data) < size:
                                    chunk = connection.recv(size - len(data))
                                    if not chunk:
                                        raise EOFError("fixture incomplete request")
                                    data.extend(chunk)
                                return bytes(data)
                            size = struct.unpack("<I", receive(4))[0]
                            if size > 131072:
                                raise ValueError("fixture request budget")
                            requests.append(json.loads(receive(size)))
                            responder(connection)
                    except Exception as error:
                        failures.append(error)

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                service = ModuleType("seaserv.service")
                service.seafile_pipe_path = path
                package = ModuleType("seaserv")
                package.service = service
                with patch.dict("sys.modules", {"seaserv": package, "seaserv.service": service}):
                    try:
                        yield requests
                    finally:
                        thread.join(3)
                        self.assertFalse(thread.is_alive(), "fixture server did not finish")
                        if failures:
                            raise failures[0]

    def test_fragmented_frame_and_fixed_service(self):
        body = b'{"ret":{"head_cmmt_id":"head"}}'
        def responder(connection):
            for byte in struct.pack("<I", len(body)) + body:
                connection.sendall(bytes([byte]))
            self.assertEqual(connection.recv(1), b"")
        with self.server(responder) as requests:
            result = _call("seafile_get_repo", ("repo",), time.monotonic() + 1)
        self.assertEqual(result, dict(head_cmmt_id="head"))
        self.assertEqual(requests[0]["service"], "seafserv-threaded-rpcserver")
        self.assertEqual(json.loads(requests[0]["request"]), ["seafile_get_repo", "repo"])

    def test_timeout_closes_real_connection(self):
        def responder(connection):
            # No response: client must close at its deadline, not leave a
            # detached transport continuing behind an HTTP timeout wrapper.
            self.assertEqual(connection.recv(1), b"")
        with self.server(responder):
            with self.assertRaises((TimeoutError, socket.timeout)):
                _call("seafile_get_repo", ("repo",), time.monotonic() + .1)

    def test_oversized_header_rejected_without_reading_body(self):
        def responder(connection):
            connection.sendall(struct.pack("<I", 0xffffffff))
            self.assertEqual(connection.recv(1), b"")
        with self.server(responder), self.assertRaises(ValueError):
            _call("seafile_get_repo", ("repo",), time.monotonic() + 1)

    def test_duplicate_or_error_response_rejected(self):
        for body in (b'{"ret":1,"ret":2}', b'{"err_code":500,"ret":"ticket"}', b'{}'):
            with self.subTest(body=body):
                def responder(connection):
                    connection.sendall(struct.pack("<I", len(body)) + body)
                with self.server(responder), self.assertRaises(ValueError):
                    _call("seafile_get_repo", ("repo",), time.monotonic() + 1)
