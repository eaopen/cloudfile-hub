"""One measured FD packet to an authenticated local native peer, not publish.

No listener or RPC is installed. The eventual caller must supply its actually
authorized store and own intent persistence before handing off any descriptor.
"""
import array
import json
import os
import select
import socket
import struct
import time
from uuid import UUID

from .staging import MeasuredStage, StageUnavailable

DOMAIN = b"CLOUDFILE-STAGE-V1\n"


def send_stage(connection, stage, *, commit_id, store_id, expected_peer_uid):
    if (not isinstance(connection, socket.socket) or not isinstance(stage, MeasuredStage) or
            type(expected_peer_uid) is not int or expected_peer_uid < 0 or
            not isinstance(commit_id, str) or str(UUID(commit_id)) != commit_id or
            not isinstance(store_id, str) or str(UUID(store_id)) != store_id or
            not hasattr(socket, "SO_PEERCRED") or connection.family != socket.AF_UNIX or
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
        raise StageUnavailable()
    pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if pid <= 0 or uid != expected_peer_uid:
        raise StageUnavailable()
    # The caller's durable server-owned intent is the correlation key. Never
    # invent a fresh key on every retry or accept an HTTP-nominated stage ID.
    stage_id = commit_id
    metadata = dict(stage_id=stage_id, store_id=store_id, length=str(stage.length), sha256=stage.sha256)
    packet = DOMAIN + json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(packet) > 1024:
        raise StageUnavailable()
    fd = stage.take_fd()
    try:
        rights = array.array("i", [fd])
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [connection], [], remaining)[1]:
                raise StageUnavailable()
            try:
                count = connection.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                    socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            except (BlockingIOError, InterruptedError):
                continue
            if count != len(packet):
                # Never send remaining bytes/FD again. The outcome is unknown,
                # not an invitation to retry a packet or publish the same edit.
                raise StageUnavailable()
            return stage_id  # Handoff only; not an indexed/native commit receipt.
    except OSError:
        raise StageUnavailable() from None
    finally:
        os.close(fd)
