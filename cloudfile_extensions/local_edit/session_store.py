"""Single-use session persistence inside real current resource authority.

Caller must hold current CE/C/lifecycle/native-version authority on this SQL
connection through commit; supplied snapshots must come from protected native
reads, never HTTP. Device proof/metadata alone cannot authorize files. No API,
commit/DDL, file transfer, activity extension or content publication occurs here.
"""
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets
from uuid import UUID, uuid4

from ..common.errors import ContractError
from ..common.validation import object_fields, identifier
from ..migration.native_status import _object
from ..resources.paths import resource_ref
from .device_proof import DeviceChallenge, _decode
from .device_store import DeviceStore
from .session_storage import require_storage


def conflict():
    return ContractError("LOCAL_SESSION_CONFLICT", "Local session changed or expired", 409)


def snapshot_json(value):
    object_fields(value, ("resource", "resource_uid", "lifecycle_ref", "base_version",
        "resource_revision", "local_open_type", "mode", "lease"))
    ref = resource_ref(value["resource"])
    if ref != value["resource"] or ref["kind"] != "file" or len(ref["path"].encode("utf-8")) > 4096:
        raise ValueError("exact protected file reference required")
    if str(UUID(value["resource_uid"])) != value["resource_uid"]:
        raise ValueError("canonical resource UID required")
    identifier(value["lifecycle_ref"], maximum=512)
    identifier(value["resource_revision"], maximum=512)
    if (not isinstance(value["base_version"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["base_version"]) or
            not isinstance(value["local_open_type"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{0,64}", value["local_open_type"]) or
            value["mode"] not in {"view", "optimistic-edit", "exclusive-edit"}):
        raise ValueError("protected file snapshot required")
    lease = value["lease"]
    if value["mode"] == "exclusive-edit":
        object_fields(lease, ("fencing", "token_digest"))
        if (not isinstance(lease["fencing"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", lease["fencing"]) or
                int(lease["fencing"]) > 2 ** 64 - 1 or not isinstance(lease["token_digest"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", lease["token_digest"])):
            raise ValueError("protected exclusive lease required")
    elif lease is not None:
        raise ValueError("non-exclusive session cannot carry a lease")
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(raw.encode("utf-8")) > 16384:
        raise ValueError("session snapshot exceeds budget")
    return raw


@dataclass(frozen=True)
class IssuedSession:
    session_id: str
    expires_at: int
    ticket: str = field(repr=False)


class LocalSessionStore:
    def __init__(self):
        self.devices = DeviceStore()

    def status(self, sql, *, provider, actor, device_id, session_id):
        # Own diagnostic/cancel does not grant file access and must still work
        # after device revocation, file moves or loss of content permissions.
        self.devices._scope(sql, provider, actor, device_id)
        require_storage(sql)
        _, device_state, device_revision = self.devices._load(sql, provider, actor, device_id)
        row = self._row(sql, provider, actor, device_id, session_id)
        sql.execute("SELECT FLOOR(UNIX_TIMESTAMP())")
        now = int(sql.fetchone()[0])
        state = row[5]
        if state in {"created", "claimed", "active"} and (now >= row[8] or state == "created" and now >= row[7]):
            state = "expired"
        return dict(session_id=session_id, state=state, revision=str(row[9]),
            device_available=device_state == "active" and device_revision == row[3])

    def cancel(self, sql, *, provider, actor, device_id, session_id, expected_revision):
        if type(expected_revision) is not int or not 1 <= expected_revision <= 2 ** 64 - 1:
            raise ValueError("positive session revision required")
        self.status(sql, provider=provider, actor=actor, device_id=device_id, session_id=session_id)
        row = self._row(sql, provider, actor, device_id, session_id)
        if row[5] == "cancelled":
            return dict(session_id=session_id, state="cancelled", revision=str(row[9])), False
        if row[5] in {"committing", "completed"} or row[9] != expected_revision or row[9] == 2 ** 64 - 1:
            # Never cancel an unknown native publish or claim it has not occurred.
            raise conflict()
        sql.execute("UPDATE cf_edit_session SET state='cancelled',revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE session_id=%s AND revision=%s AND state NOT IN ('committing','completed','cancelled')", (session_id, expected_revision))
        if sql.rowcount != 1:
            raise conflict()
        # Retain snapshot/digest and every local user file; no lease is released
        # implicitly. A separately held lease follows its own ownership protocol.
        return dict(session_id=session_id, state="cancelled", revision=str(expected_revision + 1)), True

    def _scope(self, sql, provider, actor, device_id):
        self.devices._scope(sql, provider, actor, device_id)
        require_storage(sql)
        _, state, revision = self.devices._load(sql, provider, actor, device_id)
        if state != "active":
            raise conflict()
        return revision

    @staticmethod
    def _digest(ticket):
        _decode(ticket, 32)
        return hashlib.sha256(ticket.encode("ascii")).hexdigest()

    @staticmethod
    def _row(sql, provider, actor, device_id, session_id):
        if not isinstance(session_id, str) or str(UUID(session_id)) != session_id:
            raise ValueError("canonical session required")
        sql.execute("SELECT provider,owner_user_id,device_id,device_revision,snapshot,state,ticket_digest,ticket_expires_at,expires_at,revision FROM cf_edit_session WHERE session_id=%s FOR UPDATE", (session_id,))
        row = sql.fetchone()
        if row is None or row[:3] != (provider, actor, device_id):
            raise ContractError("ACCESS_DENIED", "Local session is unavailable", 403)
        if (len(row) != 10 or row[5] not in {"created", "claimed", "active", "committing", "completed", "cancelled", "expired", "conflicted", "failed"} or
                any(type(row[index]) is not int or not 1 <= row[index] <= 2 ** 64 - 1 for index in (3, 7, 8, 9)) or
                not isinstance(row[4], str) or len(row[4].encode()) > 16384 or
                not isinstance(row[6], str) or not re.fullmatch(r"[0-9a-f]{64}", row[6])):
            raise ContractError("LOCAL_SESSION_PENDING", "Session storage requires reconciliation", 503)
        value = json.loads(row[4], object_pairs_hook=_object)
        if snapshot_json(value) != row[4]:
            raise ContractError("LOCAL_SESSION_PENDING", "Session snapshot requires reconciliation", 503)
        return row

    def create(self, sql, *, provider, actor, device_id, snapshot):
        revision = self._scope(sql, provider, actor, device_id)
        raw = snapshot_json(snapshot)
        sql.execute("SELECT FLOOR(UNIX_TIMESTAMP())")
        now = int(sql.fetchone()[0])
        ticket = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        session_id = str(uuid4())
        sql.execute("INSERT INTO cf_edit_session(session_id,provider,owner_user_id,device_id,device_revision,snapshot,state,ticket_digest,ticket_expires_at,expires_at,revision,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,'created',%s,%s,%s,1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",
            (session_id, provider, actor, device_id, revision, raw, self._digest(ticket), now + 60, now + 1800))
        return IssuedSession(session_id, now + 60, ticket)

    def _ready(self, sql, *, provider, actor, device_id, session_id, ticket, current_snapshot):
        revision = self._scope(sql, provider, actor, device_id)
        row = self._row(sql, provider, actor, device_id, session_id)
        sql.execute("SELECT FLOOR(UNIX_TIMESTAMP())")
        now = int(sql.fetchone()[0])
        if (row[3] != revision or row[5] != "created" or now >= row[7] or now >= row[8] or
                not hmac.compare_digest(row[6], self._digest(ticket)) or row[4] != snapshot_json(current_snapshot)):
            raise conflict()
        return row

    def challenge(self, sql, *, provider, actor, device_id, session_id, ticket, current_snapshot, instance):
        row = self._ready(sql, provider=provider, actor=actor, device_id=device_id,
            session_id=session_id, ticket=ticket, current_snapshot=current_snapshot)
        digest = hashlib.sha256(("cloudfile.claim.v1\n" + session_id + "\n" + row[6]).encode("ascii")).hexdigest()
        return self.devices.issue(sql, provider=provider, actor=actor, device_id=device_id,
            instance=instance, session_id=session_id, operation="claim", request_sha256=digest)

    def claim(self, sql, *, provider, actor, device_id, session_id, ticket, current_snapshot, challenge, signature, instance):
        row = self._ready(sql, provider=provider, actor=actor, device_id=device_id,
            session_id=session_id, ticket=ticket, current_snapshot=current_snapshot)
        digest = hashlib.sha256(("cloudfile.claim.v1\n" + session_id + "\n" + row[6]).encode("ascii")).hexdigest()
        if (not isinstance(challenge, DeviceChallenge) or challenge.device_id != device_id or
                challenge.session_id != session_id or challenge.instance != instance or
                challenge.operation != "claim" or challenge.request_sha256 != digest):
            raise conflict()
        self.devices.consume(sql, provider=provider, actor=actor, challenge=challenge, signature=signature)
        sql.execute("UPDATE cf_edit_session SET state='claimed',revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE session_id=%s AND state='created' AND revision=%s AND ticket_expires_at>FLOOR(UNIX_TIMESTAMP()) AND expires_at>FLOOR(UNIX_TIMESTAMP())", (session_id, row[9]))
        if sql.rowcount != 1:
            raise conflict()
        # No native ticket, plaintext lease token or upload grant returned.
        return dict(session_id=session_id, state="claimed", revision=str(row[9] + 1))
