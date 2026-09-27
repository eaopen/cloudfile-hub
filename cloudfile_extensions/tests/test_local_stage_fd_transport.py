"""Actual kernel FD handoff only; not native receiver or publication proof."""
import array
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest

from cloudfile_extensions.local_edit.fd_transport import DOMAIN, send_stage
from cloudfile_extensions.local_edit.staging import StageUnavailable, UploadStaging


@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux Unix peer credentials required")
class StageDescriptorTransportTests(unittest.TestCase):
    def test_packet_transfers_real_readonly_fd_once(self):
        with tempfile.TemporaryDirectory(prefix="cf-stage-fd-") as temporary:
            path = str(Path(temporary).resolve())
            os.chmod(path, 0o700)
            with UploadStaging(path, maximum_bytes=32) as staging:
                with staging.receive(io.BytesIO(b"measured-content"), content_length=16) as stage:
                    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    try:
                        stage_id = send_stage(left, stage,
                            commit_id="22222222-2222-4222-8222-222222222222",
                            store_id="11111111-1111-4111-8111-111111111111", expected_peer_uid=os.geteuid())
                        packet, controls, flags, _ = right.recvmsg(1024, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
                        self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                        self.assertTrue(packet.startswith(DOMAIN))
                        body = json.loads(packet[len(DOMAIN):])
                        self.assertEqual(body["stage_id"], stage_id)
                        self.assertEqual(body["length"], "16")
                        self.assertEqual(body["sha256"], stage.sha256)
                        self.assertEqual(len(controls), 1)
                        level, kind, content = controls[0]
                        self.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
                        descriptors = array.array("i")
                        descriptors.frombytes(content)
                        self.assertEqual(len(descriptors), 1)
                        fd = descriptors[0]
                        try:
                            self.assertEqual(os.pread(fd, 16, 0), b"measured-content")
                            self.assertEqual(os.fstat(fd).st_nlink, 0)
                            self.assertFalse(os.get_inheritable(fd))
                            with self.assertRaises(OSError):
                                os.write(fd, b"overwrite")
                        finally:
                            os.close(fd)
                        with self.assertRaises(StageUnavailable):
                            stage.take_fd()
                    finally:
                        left.close(); right.close()

    def test_wrong_peer_does_not_consume_stage(self):
        with tempfile.TemporaryDirectory(prefix="cf-stage-peer-") as temporary:
            path = str(Path(temporary).resolve())
            os.chmod(path, 0o700)
            with UploadStaging(path, maximum_bytes=1) as staging:
                with staging.receive(io.BytesIO(b"x"), content_length=1) as stage:
                    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    try:
                        with self.assertRaises(StageUnavailable):
                            send_stage(left, stage, commit_id="22222222-2222-4222-8222-222222222222",
                                store_id="11111111-1111-4111-8111-111111111111",
                                expected_peer_uid=os.geteuid() + 1)
                        fd = stage.take_fd()
                        os.close(fd)
                    finally:
                        left.close(); right.close()
