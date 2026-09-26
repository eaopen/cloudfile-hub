"""Device-proof current-user claim assembly; never Agent userId nomination.

Possession precheck does not consume a challenge or grant bytes. Actual claim
again checks current device/session/proof and current CE/C/native snapshot in
the resource effect transaction after latest directory preparation.
"""
from dataclasses import asdict
import hashlib
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
    def __init__(self, resources, core, *, instance, cloud_mode, secret, lifecycle_reader, version_reader):
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
