"""Actual resource authority consumers; not file transfer or publication.

The required lifecycle/version adapters must protect real native observations
under this same scope. Routes are mounted only when those providers and native
entry-point release gates are configured.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hmac
import json
import re
from uuid import UUID, uuid4

from ..common.errors import ContractError
from ..common.validation import object_fields
from ..common.validation import sequence
from ..authorization.runtime import AuthenticatedPolicyActor
from ..events.outbox import EventWriter, Outbox
from ..migration.native_status import _object
from ..resources.paths import resource_ref
from ..resources.service import ResourceService
from .device_proof import DeviceChallenge
from .device_service import DeviceManagementService
from .open_uri import OpenURI, make_open_uri
from .session_store import LocalSessionStore, snapshot_json, conflict


@dataclass(frozen=True)
class NativeLocalReadConditions:
    native_username: str = field(repr=False)
    encoded: str = field(repr=False)
    repo_id: str
    path: str
    object_id: str
    local_open_type: str = ""
    mode: str = "view"
    extension: str = ""


class LocalSessionService:
    def __init__(self, resources, *, actor, instance, version_reader, locks=None):
        if not isinstance(resources, ResourceService) or not callable(version_reader):
            raise ValueError("actual resource service and protected native version reader required")
        if locks is not None:
            raise ValueError('Legacy local editing locks are no longer supported')
        if not isinstance(actor, AuthenticatedPolicyActor) or actor.user_id != resources.read_authority.actor:
            raise ValueError("actual authenticated native browser actor required")
        DeviceChallenge(instance, "11111111-1111-4111-8111-111111111111",
            "11111111-1111-4111-8111-111111111111", "claim", "A" * 43, 1, 61, "0" * 64).message()
        if len(instance) > 255:
            raise ValueError("fixed bounded instance origin required")
        self.resources, self.instance, self.version_reader, self.locks = resources, instance, version_reader, locks
        self.sessions, self.events = LocalSessionStore(), EventWriter()
        self.owner = DeviceManagementService(resources.read_authority.preparation, actor,
            instance=instance, request_id=resources.request_id)

    def status(self, value):
        object_fields(value, ("session_id", "device_id"))
        authority = self.resources.read_authority
        return self.owner._execute(lambda sql: self.sessions.status(sql,
            provider=authority.state.provider, actor=authority.actor, **value))

    def cancel(self, value):
        object_fields(value, ("session_id", "device_id", "revision"))
        revision = sequence(value["revision"])
        authority = self.resources.read_authority
        def effect(sql):
            result, changed = self.sessions.cancel(sql, provider=authority.state.provider, actor=authority.actor,
                device_id=value["device_id"], session_id=value["session_id"], expected_revision=revision)
            if changed:
                # Stop-only metadata audit intentionally contains no old path,
                # filename or content that this user may no longer access.
                self.events.append(sql, dict(event_id=str(uuid4()), request_id=self.resources.request_id,
                    occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    actor_user_id=authority.actor, actor_kind="user", source="hub", action="local.session.cancelled",
                    result="succeeded", session_id=value["session_id"], device_id=value["device_id"], revision=result["revision"]))
            return result
        return self.owner._execute(effect)

    def _authority(self, mode):
        if mode not in {"view", "optimistic-edit", "exclusive-edit"}:
            raise ValueError("explicit local session mode required")
        return self.resources.read_authority if mode == "view" else self.resources.write_authority

    def cancel_device(self, value):
        object_fields(value, ("session_id", "device_id", "challenge", "signature"))
        object_fields(value["challenge"], ("instance", "device_id", "session_id", "operation",
            "nonce", "issued_at", "expires_at", "request_sha256"))
        challenge = DeviceChallenge(**value["challenge"])
        authority = self.resources.read_authority
        def effect(sql):
            result, changed = self.sessions.cancel_with_proof(sql,
                provider=authority.state.provider, actor=authority.actor,
                device_id=value["device_id"], session_id=value["session_id"],
                instance=self.instance, challenge=challenge, signature=value["signature"])
            if changed:
                self.events.append(sql, dict(event_id=str(uuid4()), request_id=self.resources.request_id,
                    occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    actor_user_id=authority.actor, actor_kind="user", source="hub",
                    action="local.session.cancelled", result="succeeded",
                    session_id=value["session_id"], device_id=value["device_id"], revision=result["revision"]))
            return result
        # Current own-subject/provider barriers, proof consumption, cancellation
        # and path-free audit share one transaction; no CE file grant required.
        return self.owner._execute(effect)

    def _snapshot(self, sql, ref, *, mode, allocate=False, expected_lease=None):
        store = self.resources.store
        evidence = store._validate_evidence(self.resources.reader(sql, ref))
        row = store._row(ref, evidence, locking=True)
        if row is None and allocate:
            uid = str(uuid4())
            sql.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,description,local_open_type,state,updated_at) VALUES(%s,%s,'file',%s,%s,%s,1,NULL,NULL,'active',UTC_TIMESTAMP(6))",
                (uid, ref["repo_id"], ref["path"], store._hash(ref["path"]), evidence.lifecycle_ref))
            store.mutation_hook(sql, dict(action="resource.attributes.updated",
                actor_user_id=self.resources.read_authority.actor, resource_uid=uid,
                repo_id=ref["repo_id"], path=ref["path"], revision="1"))
            row = store._row(ref, evidence, locking=True)
        if row is None:
            raise conflict()
        value = store._snapshot(ref, evidence, row)
        version = self.version_reader(sql, ref, evidence)
        lease = None
        if mode == "exclusive-edit":
            raise ContractError('EDIT_UNAVAILABLE', 'Exclusive Agent integration is not enabled', 503)
        result = dict(resource=ref, resource_uid=row["uid"], lifecycle_ref=evidence.lifecycle_ref,
            base_version=version, resource_revision=value["revision"], local_open_type=value["local_open_type"],
            mode=mode, lease=lease)
        snapshot_json(result)
        return result

    def _audit(self, sql, action, session_id, device_id, snapshot, revision):
        self.events.append(sql, dict(event_id=str(uuid4()), request_id=self.resources.request_id,
            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            actor_user_id=self.resources.read_authority.actor, actor_kind="user", source="hub",
            action=action, result="succeeded", session_id=session_id, device_id=device_id,
            repo_id=snapshot["resource"]["repo_id"], path=snapshot["resource"]["path"], resource_kind="file",
            resource_uid=snapshot["resource_uid"], revision=revision, content_version=snapshot["base_version"]))

    def create(self, value):
        object_fields(value, ("reference", "device_id", "mode"), ("lease",))
        ref = resource_ref(value["reference"])
        if ref["kind"] != "file" or len(ref["path"].encode()) > 4096:
            raise ValueError("bounded single file required")
        mode = value["mode"]
        authority = self._authority(mode)
        lease = value.get("lease")
        if mode == "exclusive-edit":
            raise ContractError('EDIT_UNAVAILABLE', 'Exclusive Agent integration is not enabled', 503)
        if lease is not None:
            raise ValueError('This mode does not accept a lease')
        def effect(sql, reference):
            snapshot = self._snapshot(sql, reference, mode=mode, allocate=True, expected_lease=lease)
            issued = self.sessions.create(sql, provider=authority.state.provider, actor=authority.actor,
                device_id=value["device_id"], snapshot=snapshot)
            self._audit(sql, "local.session.created", issued.session_id, value["device_id"], snapshot, "1")
            return dict(session_id=issued.session_id, state="created", revision="1",
                claim_expires_at=issued.expires_at,
                open_uri=make_open_uri(OpenURI(self.instance, issued.session_id, issued.ticket)))
        Outbox(self.resources.store.connection)._require_idle()
        return authority.consume(ref, effect)

    def _saved(self, value):
        # A private read only selects the resource needed for current authority.
        # No stored path/UID/mode is returned before that authority is consumed;
        # the effect re-reads and compares the full current native snapshot.
        for name in ("session_id", "device_id"):
            if not isinstance(value[name], str) or str(UUID(value[name])) != value[name]:
                raise ValueError("canonical session/device required")
        authority = self.resources.read_authority
        connection = self.resources.store.connection
        Outbox(connection)._require_idle()
        with connection.cursor() as sql:
            sql.execute("SELECT snapshot FROM cf_edit_session WHERE session_id=%s AND provider=%s AND owner_user_id=%s AND device_id=%s",
                (value["session_id"], authority.state.provider, authority.actor, value["device_id"]))
            rows = sql.fetchall()
        if len(rows) != 1 or not isinstance(rows[0][0], str) or len(rows[0][0].encode()) > 16384:
            raise ContractError("ACCESS_DENIED", "Local session is unavailable", 403)
        snapshot = json.loads(rows[0][0], object_pairs_hook=_object)
        snapshot_json(snapshot)
        return snapshot

    def challenge(self, value):
        object_fields(value, ("session_id", "device_id", "ticket"))
        return self._claim(value, confirm=False)

    def claim(self, value):
        object_fields(value, ("session_id", "device_id", "ticket", "challenge", "signature"))
        return self._claim(value, confirm=True)

    def read_challenge(self, value):
        object_fields(value, ("session_id", "device_id"))
        return self._read(value, confirm=False)

    def prepare_native_read(self, value):
        # Internal only. Never serialize this result as an Agent HTTP response.
        object_fields(value, ("session_id", "device_id", "challenge", "signature"))
        return self._read(value, confirm=True)

    def renew_challenge(self, value):
        object_fields(value, ("session_id", "device_id"))
        return self._read(value, confirm=False, renew=True)

    def renew(self, value):
        object_fields(value, ("session_id", "device_id", "challenge", "signature"))
        return self._read(value, confirm=True, renew=True)

    def _read(self, value, *, confirm, renew=False):
        saved = self._saved(value)
        authority = self._authority(saved["mode"])
        def effect(sql, reference):
            current = self._snapshot(sql, reference, mode=saved["mode"], expected_lease=saved["lease"])
            arguments = dict(provider=authority.state.provider, actor=authority.actor,
                device_id=value["device_id"], session_id=value["session_id"],
                current_snapshot=current, instance=self.instance)
            if not confirm:
                method = self.sessions.renew_challenge if renew else self.sessions.read_challenge
                return dict(challenge=asdict(method(sql, **arguments)))
            object_fields(value["challenge"], ("instance", "device_id", "session_id", "operation", "nonce",
                "issued_at", "expires_at", "request_sha256"))
            challenge = DeviceChallenge(**value["challenge"])
            if renew:
                result = self.sessions.renew(sql, **arguments, challenge=challenge, signature=value["signature"])
                self._audit(sql, "local.session.renewed", value["session_id"], value["device_id"],
                    current, result["revision"])
                return result
            proof = self.sessions.authorize_read(sql, **arguments,
                challenge=challenge, signature=value["signature"])
            subject = authority.preparation.contexts.current(authority.actor)
            if subject is None:
                raise ContractError("SUBJECT_UNAVAILABLE", "Current local subject is unavailable", 503)
            provider = authority.state.provider
            conditions = dict(path=reference["path"],
                context=dict(provider=provider, userId=authority.actor, epoch=subject["context_epoch"]),
                scopes=[dict(type="provider", provider=provider, external_id=provider),
                    dict(type="user", provider=provider, external_id=authority.actor),
                    dict(type="repo", provider="cloudfile", external_id=reference["repo_id"])],
                local_session=proof)
            encoded = json.dumps(conditions, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            if len(encoded.encode("utf-8")) > 16384:
                raise ContractError("LOCAL_SESSION_PENDING", "Native read conditions exceed budget", 503)
            return NativeLocalReadConditions(authority.state.username(authority.actor), encoded,
                reference["repo_id"], reference["path"], current["base_version"],
                current["local_open_type"], current["mode"], self._extension(reference["path"]))
        # Do not invoke native RPC while holding this separately owned SQL scope.
        return authority.consume(saved["resource"], effect)

    @staticmethod
    def _extension(path):
        name = path.rsplit("/", 1)[-1]
        suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        return suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,16}", suffix) else ""

    def _claim(self, value, *, confirm):
        saved = self._saved(value)
        authority = self._authority(saved["mode"])
        def effect(sql, reference):
            current = self._snapshot(sql, reference, mode=saved["mode"], expected_lease=saved["lease"])
            arguments = dict(provider=authority.state.provider, actor=authority.actor,
                device_id=value["device_id"], session_id=value["session_id"], ticket=value["ticket"],
                current_snapshot=current, instance=self.instance)
            if not confirm:
                return dict(challenge=asdict(self.sessions.challenge(sql, **arguments)))
            object_fields(value["challenge"], ("instance", "device_id", "session_id", "operation", "nonce",
                "issued_at", "expires_at", "request_sha256"))
            challenge = DeviceChallenge(**value["challenge"])
            result = self.sessions.claim(sql, **arguments, challenge=challenge, signature=value["signature"])
            self._audit(sql, "local.session.claimed", result["session_id"], value["device_id"], current, result["revision"])
            return result
        return authority.consume(saved["resource"], effect)
