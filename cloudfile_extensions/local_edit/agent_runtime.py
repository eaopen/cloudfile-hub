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
                    instance=self.instance, version_reader=self.version_reader,
                    agent2_exclusive_enabled=self.agent2_exclusive_enabled)
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
                    instance=self.instance, version_reader=self.version_reader,
                    agent2_exclusive_enabled=self.agent2_exclusive_enabled)
                if operation == "cancel":
                    return service.cancel_device(value)
                return service.renew(value) if operation == "renew" else service.prepare_native_read(value)
            finally:
                for authority in (resources.read_authority, resources.write_authority, resources.tag_management):
                    authority.epoch = None
                    authority.current_subject = None
                    authority.is_owner = False
                    authority.effective_access = None

    def optimistic_upload_challenge(self, value, request_id):
        """Proof for ONE optimistic local edit; never an exclusive lease."""
        return self._optimistic_upload_authority(value, request_id, signed=False)

    def optimistic_upload_authorize(self, value, request_id):
        return self._optimistic_upload_authority(value, request_id, signed=True)

    def _optimistic_upload_authority(self, value, request_id, *, signed):
        from django.conf import settings
        from .device_proof import _uuid
        import re
        from .upload_grant import seal
        self._process()
        if getattr(settings, "CLOUDFILE_AGENT2_OPTIMISTIC_UPLOAD_ENABLED", False) is not True:
            raise ContractError("EDIT_UNAVAILABLE", "Device optimistic upload is disabled", 503)
        fields = ("session_id", "device_id", "intent_id", "base_file_id",
                  "content_digest", "snapshot_size")
        object_fields(value, fields + (("challenge", "signature") if signed else ()))
        for field in ("session_id", "device_id", "intent_id"):
            _uuid(value[field])
        if (not isinstance(value["base_file_id"], str) or
                not re.fullmatch(r"[0-9a-f]{40}", value["base_file_id"]) or
                not isinstance(value["content_digest"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", value["content_digest"]) or
                type(value["snapshot_size"]) is not int or
                not 0 <= value["snapshot_size"] <= 128 * 1024 * 1024):
            raise ValueError("Explicit bounded local file snapshot required")
        identifier(request_id)
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            with connection.cursor() as sql:
                actor, saved = self._owner(sql, value)
            connection.rollback()
        if saved["mode"] != "optimistic-edit" or saved["base_version"] != value["base_file_id"]:
            raise conflict()
        with self.resources.preparation(actor, request_id) as preparation:
            native_user = preparation.state.username(actor)
            if not preparation.state.account_active(actor):
                raise ContractError("ACCESS_DENIED", "Local edit device account unavailable", 403)
            resources = ResourceService(preparation, self.core,
                cloud_mode=self.cloud_mode, request_id=request_id,
                secret=self.secret, lifecycle_reader=self.lifecycle_reader)
            authority = resources.write_authority
            try:
                def effect(sql, reference):
                    service = LocalSessionService(resources,
                        actor=AuthenticatedPolicyActor(actor, native_user),
                        instance=self.instance, version_reader=self.version_reader,
                        agent2_exclusive_enabled=self.agent2_exclusive_enabled)
                    current = service._snapshot(sql, reference, mode="optimistic-edit")
                    if snapshot_json(current) != snapshot_json(saved):
                        raise conflict()
                    owner = dict(provider=authority.state.provider, actor=actor,
                                 session_id=value["session_id"], device_id=value["device_id"])
                    row = self.sessions._read_ready(sql, **owner, current_snapshot=saved)
                    encoded = json.dumps([
                        "cloudfile.optimistic-upload.v1", value["session_id"],
                        value["device_id"], str(row[3]), str(row[9]),
                        value["intent_id"], value["base_file_id"],
                        value["content_digest"], value["snapshot_size"]],
                        separators=(",", ":"), ensure_ascii=True).encode("ascii")
                    expected_digest = hashlib.sha256(encoded).hexdigest()
                    if not signed:
                        challenge = self.sessions.devices.issue(sql,
                            provider=owner["provider"], actor=actor,
                            device_id=value["device_id"], instance=self.instance,
                            session_id=value["session_id"], operation="commit",
                            request_sha256=expected_digest)
                        return dict(challenge=asdict(challenge))
                    object_fields(value["challenge"], ("instance", "device_id", "session_id",
                        "operation", "nonce", "issued_at", "expires_at", "request_sha256"))
                    challenge = DeviceChallenge(**value["challenge"])
                    if (challenge.instance != self.instance or challenge.operation != "commit" or
                            challenge.session_id != value["session_id"] or
                            challenge.device_id != value["device_id"] or
                            challenge.request_sha256 != expected_digest):
                        raise conflict()
                    self.sessions.devices.consume(sql, provider=owner["provider"],
                        actor=actor, challenge=challenge, signature=value["signature"])
                    from .optimistic_intent import OptimisticIntentStore
                    saved_receipt = OptimisticIntentStore.prepare(sql, dict(
                        intent_id=value["intent_id"],
                        base_file_id=value["base_file_id"],
                        content_digest=value["content_digest"],
                        snapshot_size=value["snapshot_size"]),
                        session=value["session_id"],device=value["device_id"],
                        repo=reference["repo_id"])
                    if saved_receipt["state"] != "prepared":
                        raise ContractError("EDIT_CONFLICT",
                            "Original optimistic publication already completed", 409)
                    subject = preparation.contexts.current(actor)
                    if subject is None:
                        raise ContractError("SUBJECT_UNAVAILABLE", "Current subject unavailable", 503)
                    provider = authority.state.provider
                    conditions = dict(
                        path=reference["path"],
                        context=dict(provider=provider, userId=actor,
                                     epoch=subject["context_epoch"]),
                        scopes=[dict(type="provider", provider=provider, external_id=provider),
                            dict(type="user", provider=provider, external_id=actor),
                            dict(type="repo", provider="cloudfile", external_id=reference["repo_id"])],
                        agent_upload=dict(session_id=value["session_id"],
                            device_id=value["device_id"],
                            device_revision=str(row[3]),
                            session_revision=str(row[9]), intent_id=value["intent_id"]),
                        expected_file_id=value["base_file_id"])
                    grant = dict(instance=self.instance, condition=conditions,
                                 repo_id=reference["repo_id"], native_user=native_user,
                                 intent_id=value["intent_id"],
                                 content_digest=value["content_digest"],
                                 snapshot_size=value["snapshot_size"],
                                 action="optimistic-update")
                    return dict(ticket=seal(self.secret, grant), expires_in=60,
                                intent_id=value["intent_id"],
                                content_digest=value["content_digest"],
                                snapshot_size=value["snapshot_size"],
                                native_device_publish=True,
                                transfer=dict(
                                    path="/api/v2.1/cloudfile/extensions/local-edit/v1/agent/optimistic-upload/",
                                    method="POST", authorization="Bearer", redirects=False))
                return authority.consume(saved["resource"], effect)
            finally:
                for item in (resources.read_authority, resources.write_authority,
                             resources.tag_management):
                    item.epoch = None
                    item.current_subject = None
                    item.is_owner = False
                    item.effective_access = None

    def optimistic_upload_receipt(self, grant, request_id):
        """Read the Native Branch-atomic result from a sealed device grant."""
        from .optimistic_intent import OptimisticIntentStore
        self._process()
        identifier(request_id)
        value=grant["condition"]["agent_upload"]
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    result=OptimisticIntentStore.receipt(sql, value["intent_id"],
                        session=value["session_id"], device=value["device_id"],
                        repo=grant["repo_id"])
                connection.commit()
                return result
            finally:
                connection.rollback()

    def optimistic_status_challenge(self, value, request_id):
        return self._optimistic_status(value, request_id, signed=False)

    def optimistic_status(self, value, request_id):
        return self._optimistic_status(value, request_id, signed=True)

    def _optimistic_status(self, value, request_id, *, signed):
        """Status is signed with the current paired device, not a lost bearer."""
        from django.conf import settings
        from .device_proof import _uuid
        from .optimistic_intent import OptimisticIntentStore
        self._process()
        if getattr(settings, "CLOUDFILE_AGENT2_OPTIMISTIC_UPLOAD_ENABLED", False) is not True:
            raise ContractError("EDIT_UNAVAILABLE","Optimistic publication disabled",503)
        object_fields(value,("session_id","device_id","intent_id")+
                      (("challenge","signature") if signed else ()))
        for key in ("session_id","device_id","intent_id"):
            _uuid(value[key])
        identifier(request_id)
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    actor,saved=self._owner(sql,value)
                    owner=dict(provider=self.resources.provider,actor=actor,
                        device_id=value["device_id"])
                    revision=self.sessions.devices._scope(sql,**owner)
                    row=self.sessions._row(sql,**owner,session_id=value["session_id"])
                    if row[3]!=revision or saved["mode"]!="optimistic-edit":
                        raise conflict()
                    request_hash=hashlib.sha256(json.dumps([
                        "cloudfile.optimistic-status.v1",value["session_id"],
                        value["device_id"],value["intent_id"],str(revision),
                        str(row[9])],separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
                    if not signed:
                        result=dict(challenge=asdict(self.sessions.devices.issue(sql,
                            **owner,instance=self.instance,session_id=value["session_id"],
                            operation="commit",request_sha256=request_hash)))
                    else:
                        object_fields(value["challenge"],("instance","device_id",
                            "session_id","operation","nonce","issued_at",
                            "expires_at","request_sha256"))
                        c=DeviceChallenge(**value["challenge"])
                        if (c.instance!=self.instance or c.operation!="commit" or
                            c.device_id!=value["device_id"] or
                            c.session_id!=value["session_id"] or
                            c.request_sha256!=request_hash):
                            raise conflict()
                        self.sessions.devices.consume(sql,provider=owner["provider"],
                            actor=actor,challenge=c,signature=value["signature"])
                        result=dict(intent=OptimisticIntentStore.receipt(sql,
                            value["intent_id"],session=value["session_id"],
                            device=value["device_id"]))
                connection.commit()
                return result
            finally:
                connection.rollback()

    def optimistic_upload_grant(self, value, request_id):
        """Accept only a signed, short-lived, device-bound optimistic edit."""
        from django.conf import settings
        from .upload_grant import unseal
        self._process()
        if getattr(settings, "CLOUDFILE_AGENT2_OPTIMISTIC_UPLOAD_ENABLED", False) is not True:
            raise ContractError("EDIT_UNAVAILABLE", "Device optimistic upload disabled", 503)
        identifier(request_id)
        grant = unseal(self.secret, value)
        if (not isinstance(grant, dict) or
                set(grant) != {"instance", "condition", "repo_id", "native_user",
                               "intent_id", "content_digest", "snapshot_size", "action"} or
                grant["instance"] != self.instance or
                grant["action"] != "optimistic-update" or
                not isinstance(grant["condition"], dict) or
                set(grant["condition"]) != {"path", "context", "scopes",
                                            "agent_upload", "expected_file_id"}):
            raise ContractError("AUTHENTICATION_REQUIRED", "Optimistic device upload grant invalid", 401)
        return grant

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

    def _commit_device(self, value, request_id, *, signed, upload=False):
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
                            source="agent2-device", session_id=value["session_id"],
                            device_id=value["device_id"]),
                        actor=actor, holder=guard["holder"], token=value["token"],
                        guard_id=value["guard_id"], generation=int(value["generation"]),
                        credential_epoch=int(value["credential_epoch"]))
                    if upload:
                        from .upload_grant import seal, UPLOAD_PATH
                        current = preparation.contexts.current(actor)
                        if current is None:
                            raise ContractError("SUBJECT_UNAVAILABLE", "Current subject unavailable", 503)
                        provider = authority.state.provider
                        condition = dict(path=reference["path"],
                            context=dict(provider=provider, userId=actor, epoch=current["context_epoch"]),
                            scopes=[dict(type="provider", provider=provider, external_id=provider),
                                dict(type="user", provider=provider, external_id=actor),
                                dict(type="repo", provider="cloudfile", external_id=reference["repo_id"])],
                            local_commit=dict(session_id=value["session_id"], device_id=value["device_id"],
                                device_revision=str(session_row[3]), session_revision=str(session_row[9])),
                            editing=dict(repo_id=reference["repo_id"], resource_uid=resource["uid"],
                                guard_id=value["guard_id"], generation=value["generation"],
                                credential_epoch=value["credential_epoch"], holder=guard["holder"],
                                token=value["token"], intent_id=value["intent_id"], base_file_id=value["base_file_id"]))
                        ticket = seal(self.secret, dict(instance=self.instance, condition=condition, native_user=native_user,
                            content_digest=value["content_digest"], snapshot_size=value["snapshot_size"],
                            action=value["action"]))
                        return dict(ticket=ticket, expires_in=60, intent_id=value["intent_id"],
                            content_digest=value["content_digest"], snapshot_size=value["snapshot_size"],
                            native_device_publish=True, transfer=dict(path=UPLOAD_PATH, method="POST",
                                authorization="Bearer", redirects=False))
                    return dict(intent_id=value["intent_id"], state=prepared["state"],
                        device_authorized=True, publication="not_started")
                return authority.consume(ref, effect)
            finally:
                for item in (resources.read_authority, resources.write_authority, resources.tag_management):
                    item.epoch = None
                    item.current_subject = None
                    item.is_owner = False
                    item.effective_access = None

    def commit_upload_authorize(self, value, request_id):
        return self._commit_device(value, request_id, signed=True, upload=True)

    def upload_grant(self, value, request_id):
        from .upload_grant import unseal
        self._process()
        if not self.agent2_exclusive_enabled:
            raise ContractError("EDIT_UNAVAILABLE", "Device publishing disabled", 503)
        identifier(request_id)
        grant = unseal(self.secret, value)
        if grant.get("instance") != self.instance:
            raise ContractError("AUTHENTICATION_REQUIRED", "Upload origin changed", 401)
        return grant

    def commit_status_challenge(self, value, request_id):
        return self._commit_status(value, request_id, signed=False)

    def commit_status(self, value, request_id):
        return self._commit_status(value, request_id, signed=True)

    def _commit_status(self, value, request_id, *, signed):
        from .device_proof import _uuid
        self._process()
        if not self.agent2_exclusive_enabled:
            raise ContractError("EDIT_UNAVAILABLE", "Device publishing disabled", 503)
        object_fields(value, ("session_id", "device_id", "intent_id") +
            (("challenge", "signature") if signed else ()))
        for name in ("session_id", "device_id", "intent_id"):
            _uuid(value[name])
        identifier(request_id)
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    actor, saved = self._owner(sql, value)
                    revision = self.sessions._scope(sql, self.resources.provider, actor, value["device_id"])
                    row = self.sessions._row(sql, self.resources.provider, actor,
                        value["device_id"], value["session_id"])
                    if row[3] != revision or saved["mode"] != "exclusive-edit":
                        raise conflict()
                    digest = hashlib.sha256(json.dumps(["cloudfile.commit-status.v1",
                        value["session_id"], value["device_id"], value["intent_id"],
                        str(revision), str(row[9])], separators=(",", ":")).encode()).hexdigest()
                    if not signed:
                        result = dict(challenge=asdict(self.sessions.devices.issue(sql,
                            provider=self.resources.provider, actor=actor, device_id=value["device_id"],
                            instance=self.instance, session_id=value["session_id"],
                            operation="commit", request_sha256=digest)))
                    else:
                        object_fields(value["challenge"], ("instance", "device_id", "session_id",
                            "operation", "nonce", "issued_at", "expires_at", "request_sha256"))
                        challenge = DeviceChallenge(**value["challenge"])
                        if (challenge.instance != self.instance or challenge.operation != "commit" or
                                challenge.session_id != value["session_id"] or
                                challenge.device_id != value["device_id"] or challenge.request_sha256 != digest):
                            raise conflict()
                        self.sessions.devices.consume(sql, provider=self.resources.provider,
                            actor=actor, challenge=challenge, signature=value["signature"])
                        result = dict(intent=self._device_receipt(sql, saved["resource_uid"],
                            value["session_id"], value["device_id"], value["intent_id"]))
                connection.commit()
                return result
            finally:
                connection.rollback()

    @staticmethod
    def _device_receipt(sql, uid, session, device, intent):
        from ..editing.store import EditingStore
        try:
            result = EditingStore.intent(sql, uid=uid, intent_id=intent)
        except ContractError as error:
            if error.code != "NOT_FOUND":
                raise
            return dict(intent_id=intent, state="not-found")
        metadata = result.get("snapshot") or {}
        if (metadata.get("source") != "agent2-device" or metadata.get("session_id") != session or
                metadata.get("device_id") != device):
            raise ContractError("ACCESS_DENIED", "Intent is not owned by this device session", 403)
        return {key: result[key] for key in ("intent_id", "state", "result_file_id",
            "content_digest", "expected_file_id", "action", "checked_in") if result[key] is not None}

    def upload_receipt(self, value, request_id):
        # Private HTTP adapter call only; value came from the authenticated grant.
        self._process()
        if not self.agent2_exclusive_enabled:
            raise ContractError("EDIT_UNAVAILABLE", "Device publishing disabled", 503)
        condition = value["condition"]
        edit, session = condition["editing"], condition["local_commit"]
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    result = self._device_receipt(sql, edit["resource_uid"], session["session_id"],
                        session["device_id"], edit["intent_id"])
                connection.commit()
                return result
            finally:
                connection.rollback()

    @staticmethod
    def _lease_digest(session_id, device_id, session_row, purpose):
        if purpose not in ("receive", "confirm", "renew"):
            raise ValueError("Supported device Checkout handoff action required")
        snapshot_hash = hashlib.sha256(session_row[4].encode("utf-8")).hexdigest()
        body = json.dumps(["cloudfile.lease-handoff.v1", purpose, session_id,
            device_id, str(session_row[3]), str(session_row[9]), snapshot_hash],
            ensure_ascii=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(body).hexdigest()

    def lease_challenge(self, value, request_id):
        return self._lease_handoff(value, request_id, purpose="receive", signed=False)

    def lease_receive(self, value, request_id):
        return self._lease_handoff(value, request_id, purpose="receive", signed=True)

    def lease_confirm_challenge(self, value, request_id):
        return self._lease_handoff(value, request_id, purpose="confirm", signed=False)

    def lease_confirm(self, value, request_id):
        return self._lease_handoff(value, request_id, purpose="confirm", signed=True)

    def lease_renew_challenge(self, value, request_id):
        return self._lease_handoff(value, request_id, purpose="renew", signed=False)

    def lease_renew(self, value, request_id):
        return self._lease_handoff(value, request_id, purpose="renew", signed=True)

    def _lease_handoff(self, value, request_id, *, purpose, signed):
        """Signed, current-device Checkout delivery with durable-journal ACK.

        Challenge reads carry no Checkout credential. A receive result may be
        retried only by the same live device with a new signature, until the
        Agent reports that the private journal was persisted. Confirmation
        erases ciphertext and retains an acknowledgement marker.
        """
        from .lease_escrow import CheckoutLeaseEscrow
        self._process()
        if not self.agent2_exclusive_enabled:
            raise ContractError("EDIT_UNAVAILABLE", "Device Checkout is disabled", 503)
        object_fields(value, ("session_id", "device_id") +
            (("challenge", "signature") if signed else ()))
        identifier(request_id)
        with self.resources.connection() as connection:
            Outbox(connection)._require_idle()
            connection.begin()
            try:
                with connection.cursor() as sql:
                    actor, saved = self._owner(sql, value)
                    if saved["mode"] != "exclusive-edit":
                        raise conflict()
                    row = self.sessions._read_ready(sql,
                        provider=self.resources.provider, actor=actor,
                        device_id=value["device_id"], session_id=value["session_id"],
                        current_snapshot=saved)
                    expected = self._lease_digest(value["session_id"],
                        value["device_id"], row, purpose)
                    if not signed:
                        challenge = self.sessions.devices.issue(sql,
                            provider=self.resources.provider, actor=actor,
                            device_id=value["device_id"], instance=self.instance,
                            session_id=value["session_id"], operation="lease",
                            request_sha256=expected)
                        result = dict(challenge=asdict(challenge))
                if not signed:
                    connection.commit()
                    return result
            finally:
                connection.rollback()
        if not signed:
            raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Lease challenge unavailable", 503)
        object_fields(value["challenge"], ("instance", "device_id", "session_id",
            "operation", "nonce", "issued_at", "expires_at", "request_sha256"))
        challenge = DeviceChallenge(**value["challenge"])
        if (challenge.instance != self.instance or challenge.operation != "lease" or
                challenge.session_id != value["session_id"] or
                challenge.device_id != value["device_id"] or
                challenge.request_sha256 != expected):
            raise conflict()
        with self.resources.preparation(actor, request_id) as preparation:
            native_user = preparation.state.username(actor)
            if not preparation.state.account_active(actor):
                raise ContractError("ACCESS_DENIED", "Current device account unavailable", 403)
            resources = ResourceService(preparation, self.core,
                cloud_mode=self.cloud_mode, request_id=request_id,
                secret=self.secret, lifecycle_reader=self.lifecycle_reader)
            authority = resources.write_authority
            try:
                def effect(sql, reference):
                    session_service = LocalSessionService(resources,
                        actor=AuthenticatedPolicyActor(actor, native_user),
                        instance=self.instance, version_reader=self.version_reader,
                        agent2_exclusive_enabled=True)
                    current = session_service._snapshot(sql, reference,
                        mode="exclusive-edit", expected_lease=saved["lease"])
                    if snapshot_json(current) != snapshot_json(saved):
                        raise conflict()
                    row = self.sessions._read_ready(sql, provider=authority.state.provider,
                        actor=actor, device_id=value["device_id"],
                        session_id=value["session_id"], current_snapshot=saved)
                    if challenge.request_sha256 != self._lease_digest(
                            value["session_id"], value["device_id"], row, purpose):
                        raise conflict()
                    self.sessions.devices.consume(sql, provider=authority.state.provider,
                        actor=actor, challenge=challenge, signature=value["signature"])
                    if purpose == "renew":
                        # A live signed device may renew *only its own* current
                        # checkout, within the existing hard deadline. No
                        # browser cookie, user-nominated path or token digest
                        # supplied by the device can authorize a different lock.
                        from ..editing.store import EditingStore
                        evidence = resources.store._validate_evidence(resources.reader(sql, reference))
                        resource = resources.store._row(reference, evidence, locking=True)
                        if resource is None or resource["uid"] != saved["resource_uid"]:
                            raise conflict()
                        guard = EditingStore().load(sql, resource["uid"],
                            reference["repo_id"], evidence.lifecycle_ref)
                        if (not guard or guard["mode"] != "checkout" or not guard["credential_active"] or
                                guard["owner"] != actor or guard["owner_native_user"] != native_user or
                                guard["guard_id"] is None or
                                str(guard["generation"]) != saved["lease"]["fencing"] or
                                not hmac.compare_digest(guard["proof_digest"],
                                    saved["lease"]["token_digest"])):
                            raise conflict()
                        sql.execute(
                            "UPDATE cf_edit_guard SET lease_until=LEAST(hard_expire_at,"
                            "TIMESTAMPADD(SECOND,600,UTC_TIMESTAMP(6))) "
                            "WHERE resource_uid=%s AND guard_id=%s AND generation=%s "
                            "AND owner=%s AND proof_digest=%s AND mode='checkout' "
                            "AND lease_until>UTC_TIMESTAMP(6) AND hard_expire_at>UTC_TIMESTAMP(6)",
                            (resource["uid"], guard["guard_id"], guard["generation"],
                             actor, guard["proof_digest"]))
                        if sql.rowcount != 1:
                            raise conflict()
                        sql.execute(
                            "UPDATE cf_edit_session "
                            "SET expires_at=GREATEST(expires_at,FLOOR(UNIX_TIMESTAMP())+1800),"
                            "updated_at=UTC_TIMESTAMP(6) "
                            "WHERE session_id=%s AND device_id=%s AND state IN ('claimed','active') "
                            "AND expires_at>FLOOR(UNIX_TIMESTAMP())",
                            (value["session_id"], value["device_id"]))
                        return dict(session_id=value["session_id"], renewed=True)
                    escrow = CheckoutLeaseEscrow()
                    if purpose == "confirm":
                        escrow.confirm(sql, session=value["session_id"])
                        return dict(confirmed=True, session_id=value["session_id"])
                    lease = escrow.receive(sql, secret=self.secret,
                        instance=self.instance, session=value["session_id"],
                        device=value["device_id"], actor=actor,
                        expected_digest=saved["lease"]["token_digest"])
                    if (lease["base_file_id"] != saved["base_version"] or
                            lease["generation"] != saved["lease"]["fencing"]):
                        raise conflict()
                    return dict(session_id=value["session_id"], lease=lease)
                return authority.consume(saved["resource"], effect)
            finally:
                for item in (resources.read_authority, resources.write_authority,
                             resources.tag_management):
                    item.epoch = None
                    item.current_subject = None
                    item.is_owner = False
                    item.effective_access = None
