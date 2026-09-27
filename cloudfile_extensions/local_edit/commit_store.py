"""Durable device intent under caller-owned actual current WRITE authority.

No public API, inferred authorization, commit, native I/O or completion writer.
The native final transaction must own Branch/receipt/session/events completion.
"""
import hashlib
import json
import os
import re
from uuid import UUID, uuid4

from ..migration.native_status import _object
from .commit_storage import require_storage
from .device_proof import DeviceChallenge
from .session_store import LocalSessionStore, conflict, snapshot_json
from .staging import MeasuredStage


class LocalCommitStore:
    def __init__(self):
        self.sessions = LocalSessionStore()

    @staticmethod
    def _receipt(row):
        return dict(commit_id=row[0], session_id=row[1], state=row[11], revision=str(row[14]))

    def _row(self, sql, *, provider, actor, commit_id):
        if not isinstance(commit_id, str) or str(UUID(commit_id)) != commit_id:
            raise ValueError("Canonical intent required")
        sql.execute("SELECT commit_id,session_id,provider,owner_user_id,device_id,device_revision,session_revision,store_id,snapshot,upload_sha256,upload_bytes,state,new_file_id,published_head,revision FROM cf_edit_commit WHERE commit_id=%s FOR UPDATE", (commit_id,))
        row = sql.fetchone()
        if row is None or row[2:4] != (provider, actor):
            raise conflict()
        if (len(row) != 15 or row[11] not in {"prepared", "committing", "completed", "conflicted", "failed"} or
                any(type(row[index]) is not int or not 1 <= row[index] <= 2 ** 64 - 1 for index in (5, 6, 14)) or
                type(row[10]) is not int or not 0 <= row[10] <= 2 ** 63 - 1 or
                not isinstance(row[9], str) or not re.fullmatch(r"[0-9a-f]{64}", row[9]) or
                not isinstance(row[8], str) or len(row[8].encode()) > 16384):
            raise conflict()
        if (any(not isinstance(row[index], str) or str(UUID(row[index])) != row[index] for index in (0, 1, 4, 7)) or
                snapshot_json(json.loads(row[8], object_pairs_hook=_object)) != row[8] or
                any(value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)) for value in row[12:14]) or
                row[11] == "completed" and any(value is None for value in row[12:14]) or
                row[11] != "completed" and row[13] is not None):
            raise conflict()
        return row

    def status(self, sql, *, provider, actor, device_id, commit_id):
        require_storage(sql)
        row = self._row(sql, provider=provider, actor=actor, commit_id=commit_id)
        if row[4] != device_id:
            raise conflict()
        # Own stop/diagnostic scope only, even if the device was revoked or
        # content moved. Native completion IDs are outcomes, not download grants.
        self.sessions.status(sql, provider=provider, actor=actor, device_id=device_id, session_id=row[1])
        return dict(**self._receipt(row), new_file_id=row[12], published_head=row[13])

    def prepare(self, sql, *, provider, actor, device_id, session_id, current_snapshot, store_id, stage):
        require_storage(sql)
        if (current_snapshot.get("mode") not in {"optimistic-edit", "exclusive-edit"} or
                not isinstance(store_id, str) or str(UUID(store_id)) != store_id or
                not isinstance(stage, MeasuredStage) or stage._pid != os.getpid() or stage._fd is None or
                type(stage.length) is not int or not 0 <= stage.length <= 2 ** 63 - 1 or
                not isinstance(stage.sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", stage.sha256)):
            raise ValueError("Actual owned measured stage and protected editable target required")
        session = self.sessions._read_ready(sql, provider=provider, actor=actor, device_id=device_id,
            session_id=session_id, current_snapshot=current_snapshot)
        sql.execute("SELECT commit_id FROM cf_edit_commit WHERE session_id=%s FOR UPDATE", (session_id,))
        existing = sql.fetchone()
        if existing:
            row = self._row(sql, provider=provider, actor=actor, commit_id=existing[0])
            if (row[4:7] != (device_id, session[3], session[9]) or row[7:11] !=
                    (store_id, session[4], stage.sha256, stage.length) or row[11] != "prepared"):
                raise conflict()
            return self._receipt(row)
        commit_id = str(uuid4())
        sql.execute("INSERT INTO cf_edit_commit(commit_id,session_id,provider,owner_user_id,device_id,device_revision,session_revision,store_id,snapshot,upload_sha256,upload_bytes,state,new_file_id,published_head,revision,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared',NULL,NULL,1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",
            (commit_id, session_id, provider, actor, device_id, session[3], session[9], store_id,
             session[4], stage.sha256, stage.length))
        return dict(commit_id=commit_id, session_id=session_id, state="prepared", revision="1")

    @staticmethod
    def _digest(row):
        value = ["cloudfile.commit.v1", row[0], row[1], str(row[5]), str(row[6]),
            row[7], row[9], str(row[10]), hashlib.sha256(row[8].encode()).hexdigest(), str(row[14])]
        return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()

    def _ready(self, sql, *, provider, actor, device_id, commit_id, current_snapshot):
        require_storage(sql)
        row = self._row(sql, provider=provider, actor=actor, commit_id=commit_id)
        session = self.sessions._read_ready(sql, provider=provider, actor=actor, device_id=device_id,
            session_id=row[1], current_snapshot=current_snapshot)
        if (row[4:7] != (device_id, session[3], session[9]) or row[8] != snapshot_json(current_snapshot) or
                current_snapshot["mode"] == "view" or row[11] != "prepared" or
                row[14] == 2 ** 64 - 1 or session[9] == 2 ** 64 - 1):
            raise conflict()
        return row

    def challenge(self, sql, *, provider, actor, device_id, commit_id, current_snapshot, instance):
        row = self._ready(sql, provider=provider, actor=actor, device_id=device_id,
            commit_id=commit_id, current_snapshot=current_snapshot)
        return self.sessions.devices.issue(sql, provider=provider, actor=actor, device_id=device_id,
            instance=instance, session_id=row[1], operation="commit", request_sha256=self._digest(row))

    def begin(self, sql, *, provider, actor, device_id, commit_id, current_snapshot, instance, challenge, signature):
        row = self._ready(sql, provider=provider, actor=actor, device_id=device_id,
            commit_id=commit_id, current_snapshot=current_snapshot)
        if (not isinstance(challenge, DeviceChallenge) or challenge.instance != instance or
                challenge.device_id != device_id or challenge.session_id != row[1] or
                challenge.operation != "commit" or challenge.request_sha256 != self._digest(row)):
            raise conflict()
        self.sessions.devices.consume(sql, provider=provider, actor=actor,
            challenge=challenge, signature=signature)
        sql.execute("UPDATE cf_edit_commit SET state='committing',revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE commit_id=%s AND revision=%s AND state='prepared'", (commit_id, row[14]))
        if sql.rowcount != 1:
            raise conflict()
        sql.execute("UPDATE cf_edit_session SET state='committing',revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE session_id=%s AND revision=%s AND state IN ('claimed','active') AND expires_at>FLOOR(UNIX_TIMESTAMP())", (row[1], row[6]))
        if sql.rowcount != 1:
            raise conflict()
        return dict(commit_id=commit_id, session_id=row[1], state="committing", revision=str(row[14] + 1))
