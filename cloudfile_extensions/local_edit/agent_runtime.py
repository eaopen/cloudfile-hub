"""Device-proof current-user claim assembly; never Agent userId nomination.

Possession precheck does not consume a challenge or grant bytes. Actual claim
again checks current device/session/proof and current CE/C/native snapshot in
the resource effect transaction after latest directory preparation.
"""
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from uuid import UUID

from ..authorization.core import PolicyCore
from ..authorization.resources import PolicyResources
from ..authorization.runtime import AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier, object_fields
from ..events.outbox import Outbox
from ..migration.native_status import _object
from ..resources.service import ResourceService
from .device_proof import DeviceChallenge
from .session_service import LocalSessionService
from .session_store import LocalSessionStore, snapshot_json, conflict


class AgentClaimRuntime:
    def __init__(self, resources, core, *, instance, cloud_mode, secret, lifecycle_reader, version_reader, agent2_exclusive_enabled=False):
        if (not isinstance(resources, PolicyResources) or not isinstance(core, PolicyCore) or
                type(cloud_mode) is not bool or not isinstance(secret, bytes) or len(secret) < 32 or
                not callable(lifecycle_reader) or not callable(version_reader)):
            raise ValueError("actual owned policy/resources and native lifecycle/version adapters required")
        DeviceChallenge(instance, "11111111-1111-4111-8111-111111111111",
            "11111111-1111-4111-8111-111111111111", "claim", "A" * 43, 1, 61, "0" * 64).message()
        if len(instance) > 255:
            raise ValueError("fixed bounded instance origin required")
        self.resources, self.core, self.instance = resources, core, instance
        self.cloud_mode, self.secret = cloud_mode, secret
        self.lifecycle_reader, self.version_reader = lifecycle_reader, version_reader
        if type(agent2_exclusive_enabled) is not bool:
            raise ValueError("Explicit Agent2 exclusive feature flag required")
        self.agent2_exclusive_enabled = agent2_exclusive_enabled
        self.sessions = LocalSessionStore()
        self.pid = os.getpid()

    def _process(self):
        if os.getpid() != self.pid:
            raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Device runtime requires post-fork ownership", 503)

    def _owner(self, sql, value):
        for key in ("session_id", "device_id"):
            if not isinstance(value[key], str) or str(UUID(value[key])) != value[key]:
                raise ValueError("canonical session/device required")
        sql.execute("SELECT provider,owner_user_id,device_id,snapshot FROM cf_edit_session WHERE session_id=%s", (value["session_id"],))
        row = sql.fetchone()
        if row is None or row[0] != self.resources.provider or row[2] != value["device_id"]:
            raise ContractError("AUTHENTICATION_REQUIRED", "Device session proof is unavailable", 401)
        identifier(row[1], maximum=225)
        if not isinstance(row[3], str) or len(row[3].encode()) > 16384:
            raise conflict()
        snapshot = json.loads(row[3], object_pairs_hook=_object)
        snapshot_json(snapshot)
        return row[1], snapshot

    def challenge(self, value, request_id):
        self._process()
        object_fields(value, ("session_id", "device_id", "ticket"))
        identifier(request_id)
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    actor, saved = self._owner(sql, value)
                    # Ticket possession permits only a bounded public challenge,
                    # never directory fetch, path disclosure, native tickets or
                    # device enrollment. Device/session state still checked.
                    challenge = self.sessions.challenge(sql, provider=self.resources.provider, actor=actor,
                        device_id=value["device_id"], session_id=value["session_id"], ticket=value["ticket"],
                        current_snapshot=saved, instance=self.instance)
                connection.commit()
                return dict(challenge=asdict(challenge))
            finally:
                connection.rollback()

    def claim(self, value, request_id):
        self._process()
        object_fields(value, ("session_id", "device_id", "ticket", "challenge", "signature"))
        identifier(request_id)
        object_fields(value["challenge"], ("instance", "device_id", "session_id", "operation", "nonce",
            "issued_at", "expires_at", "request_sha256"))
        challenge = DeviceChallenge(**value["challenge"])
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    actor, saved = self._owner(sql, value)
                    row = self.sessions._ready(sql, provider=self.resources.provider, actor=actor,
                        device_id=value["device_id"], session_id=value["session_id"], ticket=value["ticket"], current_snapshot=saved)
                    digest = hashlib.sha256(("cloudfile.claim.v1\n" + value["session_id"] + "\n" + row[6]).encode("ascii")).hexdigest()
                    if (challenge.instance != self.instance or challenge.operation != "claim" or
                            challenge.session_id != value["session_id"] or challenge.device_id != value["device_id"] or
                            challenge.request_sha256 != digest):
                        raise conflict()
                    self.sessions.devices.verify_saved(sql, provider=self.resources.provider,
                        actor=actor, challenge=challenge, signature=value["signature"])
            finally:
                # Only a signature/provenance precheck. Never consume proof on
                # this separate connection; final claim owns actual consumption.
                connection.rollback()
        with self.resources.preparation(actor, request_id) as preparation:
            username = preparation.state.username(actor)
            if not preparation.state.account_active(actor):
                raise ContractError("ACCESS_DENIED", "Native device account is unavailable", 403)
            resources = ResourceService(preparation, self.core, cloud_mode=self.cloud_mode,
                request_id=request_id, secret=self.secret, lifecycle_reader=self.lifecycle_reader)
            try:
                service = LocalSessionService(resources, actor=AuthenticatedPolicyActor(actor, username),
                    instance=self.instance, version_reader=self.version_reader)
                # No stale precheck grant is returned. Current ResourceService
                # prepares latest subjects and repeats device proof/expiry under
                # current native CE/C/file snapshot before committing claim.
                return service.claim(value)
            finally:
                for authority in (resources.read_authority, resources.write_authority, resources.tag_management):
                    authority.epoch = None
                    authority.current_subject = None
                    authority.is_owner = False
                    authority.effective_access = None

    def read_challenge(self, value, request_id):
        """Original URI secret permits only a public nonce, never file bytes.

        Its initial claim expiry no longer applies after claim; the current
        device/session expiry and snapshot still apply. The ticket is never
        accepted as a standalone download credential.
        """
        return self._session_challenge(value, request_id, operation="read")

    def renew_challenge(self, value, request_id):
        return self._session_challenge(value, request_id, operation="renew")

    def cancel_challenge(self, value, request_id):
        return self._session_challenge(value, request_id, operation="cancel")

    def _session_challenge(self, value, request_id, *, operation):
        self._process()
        object_fields(value, ("session_id", "device_id", "ticket"))
        identifier(request_id)
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    actor, saved = self._owner(sql, value)
                    owner = dict(provider=self.resources.provider, actor=actor,
                        device_id=value["device_id"], session_id=value["session_id"])
                    row = (self.sessions._cancel_ready(sql, **owner) if operation == "cancel" else
                        self.sessions._read_ready(sql, **owner, current_snapshot=saved))
                    if not hmac.compare_digest(row[6], self.sessions._digest(value["ticket"])):
                        raise conflict()
                    if operation == "cancel":
                        challenge = self.sessions.cancel_challenge(sql, **owner, instance=self.instance)
                    else:
                        method = self.sessions.renew_challenge if operation == "renew" else self.sessions.read_challenge
                        challenge = method(sql, **owner, current_snapshot=saved, instance=self.instance)
                connection.commit()
                return dict(challenge=asdict(challenge))
            finally:
                connection.rollback()

    def prepare_native_read(self, value, request_id):
        """Private adapter result, not serializable Agent HTTP output.

        Actual native read RPC and transfer adapter must consume the result
        after all Hub SQL scopes close and repeat every native final guard.
        """
        return self._session_effect(value, request_id, operation="read")

    def renew(self, value, request_id):
        return self._session_effect(value, request_id, operation="renew")

    def cancel(self, value, request_id):
        return self._session_effect(value, request_id, operation="cancel")

    def _session_effect(self, value, request_id, *, operation):
        self._process()
        object_fields(value, ("session_id", "device_id", "challenge", "signature"))
        identifier(request_id)
        object_fields(value["challenge"], ("instance", "device_id", "session_id", "operation", "nonce",
            "issued_at", "expires_at", "request_sha256"))
        challenge = DeviceChallenge(**value["challenge"])
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    actor, saved = self._owner(sql, value)
                    owner = dict(provider=self.resources.provider, actor=actor,
                        device_id=value["device_id"], session_id=value["session_id"])
                    row = (self.sessions._cancel_ready(sql, **owner) if operation == "cancel" else
                        self.sessions._read_ready(sql, **owner, current_snapshot=saved))
                    digest = {"renew": self.sessions._renew_digest, "read": self.sessions._read_digest,
                        "cancel": self.sessions._cancel_digest}[operation]
                    if (challenge.instance != self.instance or challenge.operation != operation or
                            challenge.session_id != value["session_id"] or challenge.device_id != value["device_id"] or
                            challenge.request_sha256 != digest(value["session_id"], row)):
                        raise conflict()
                    self.sessions.devices.verify_saved(sql, provider=self.resources.provider,
                        actor=actor, challenge=challenge, signature=value["signature"])
            finally:
                connection.rollback()
        # Verified device possession precedes the employee directory request.
        # The saved snapshot only selects the target; the final authority checks
        # a protected current snapshot and consumes proof in its own transaction.
        with self.resources.preparation(actor, request_id) as preparation:
            username = preparation.state.username(actor)
            if not preparation.state.account_active(actor):
                raise ContractError("ACCESS_DENIED", "Native device account is unavailable", 403)
            resources = ResourceService(preparation, self.core, cloud_mode=self.cloud_mode,
                request_id=request_id, secret=self.secret, lifecycle_reader=self.lifecycle_reader)
            try:
                service = LocalSessionService(resources, actor=AuthenticatedPolicyActor(actor, username),
                    instance=self.instance, version_reader=self.version_reader)
                if operation == "cancel":
                    return service.cancel_device(value)
                return service.renew(value) if operation == "renew" else service.prepare_native_read(value)
            finally:
                for authority in (resources.read_authority, resources.write_authority, resources.tag_management):
                    authority.epoch = None
                    authority.current_subject = None
                    authority.is_owner = False
                    authority.effective_access = None

    def commit_challenge(self, value, request_id):
        """Device-side signed one-file PREPARE; does not authorize file bytes."""
        return self._commit_device(value, request_id, signed=False)

    def commit_authorize(self, value, request_id):
        """Consume device proof and persist the intent in the same ACL SQL txn.

        No file publication or long-lived write bearer is returned. The native
        guarded publisher must still receive independently trusted current
        device-session evidence; absent that product adapter this remains off.
        """
        return self._commit_device(value, request_id, signed=True)

    def _commit_device(self, value, request_id, *, signed):
        from ..editing.store import EditingStore
        from .commit_contract import validate_request, bind_request
        self._process()
        if not self.agent2_exclusive_enabled:
            raise ContractError("EDIT_UNAVAILABLE", "Agent2 device publishing is disabled", 503)
        identifier(request_id)
        validate_request(value, signed=signed)
        # Resolve identity and the saved resource without trusting userId/path
        # from a device body; this is a selector, not authorization.
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            with connection.cursor() as sql:
                actor, saved = self._owner(sql, value)
            connection.rollback()
        if saved["mode"] != "exclusive-edit":
            raise ContractError("EDIT_UNAVAILABLE", "Only an existing exclusive session may commit", 503)
        ref = saved["resource"]
        with self.resources.preparation(actor, request_id) as preparation:
            native_user = preparation.state.username(actor)
            if not preparation.state.account_active(actor):
                raise ContractError("ACCESS_DENIED", "Current device account is unavailable", 403)
            resources = ResourceService(preparation, self.core,
                cloud_mode=self.cloud_mode, request_id=request_id,
                secret=self.secret, lifecycle_reader=self.lifecycle_reader)
            authority = resources.write_authority
            try:
                def effect(sql, reference):
                    evidence = resources.store._validate_evidence(resources.reader(sql, reference))
                    resource = resources.store._row(reference, evidence, locking=True)
                    if (resource is None or resource["uid"] != saved["resource_uid"] or
                            evidence.lifecycle_ref != saved["lifecycle_ref"] or
                            str(resource["revision"]) != str(saved["resource_revision"])):
                        raise conflict()
                    current_file = self.version_reader(sql, reference, evidence)
                    if current_file != value["base_file_id"] or current_file != saved["base_version"]:
                        raise ContractError("RESOURCE_VERSION_CONFLICT", "Native version changed", 409)
                    edits = EditingStore()
                    guard = edits.load(sql, resource["uid"], reference["repo_id"], evidence.lifecycle_ref)
                    if not guard or guard["owner"] != actor:
                        raise ContractError("ACCESS_DENIED", "Current guarded edit owner required", 403)
                    owner = dict(provider=authority.state.provider, actor=actor,
                        device_id=value["device_id"], session_id=value["session_id"])
                    session_row = self.sessions._read_ready(sql, **owner, current_snapshot=saved)
                    request_digest = bind_request(value, snapshot=saved,
                        session_row=session_row, edit_guard=guard, current_native=native_user)
                    if not signed:
                        challenge = self.sessions.devices.issue(sql, **{
                            "provider": owner["provider"], "actor": actor,
                            "device_id":value["device_id"]},
                            instance=self.instance, session_id=value["session_id"],
                            operation="commit", request_sha256=request_digest)
                        return dict(challenge=asdict(challenge))
                    object_fields(value["challenge"], ("instance", "device_id", "session_id",
                        "operation", "nonce", "issued_at", "expires_at", "request_sha256"))
                    challenge = DeviceChallenge(**value["challenge"])
                    if (challenge.instance != self.instance or challenge.operation != "commit" or
                            challenge.device_id != value["device_id"] or
                            challenge.session_id != value["session_id"] or
                            challenge.request_sha256 != request_digest):
                        raise conflict()
                    self.sessions.devices.consume(sql, provider=owner["provider"],
                        actor=actor, challenge=challenge, signature=value["signature"])
                    prepared = edits.prepare(sql, uid=resource["uid"],
                        repo=reference["repo_id"], lifecycle=evidence.lifecycle_ref,
                        intent_id=value["intent_id"], expected_file_id=value["base_file_id"],
                        staged_file_id=None, content_digest=value["content_digest"],
                        action=value["action"],
                        snapshot=dict(id=value["intent_id"], size=value["snapshot_size"],
                            source="agent2-device"),
                        actor=actor, holder=guard["holder"], token=value["token"],
                        guard_id=value["guard_id"], generation=int(value["generation"]),
                        credential_epoch=int(value["credential_epoch"]))
                    return dict(intent_id=value["intent_id"], state=prepared["state"],
                        device_authorized=True, publication="not_started")
                return authority.consume(ref, effect)
            finally:
                for item in (resources.read_authority, resources.write_authority, resources.tag_management):
                    item.epoch = None
                    item.current_subject = None
                    item.is_owner = False
                    item.effective_access = None
