"""Browser-authenticated own-device pairing, not Agent/file authorization."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from ..authorization.runtime import AuthenticatedPolicyActor
from ..common.errors import ContractError
from ..common.validation import identifier, object_fields, sequence
from ..directory.preparation import SubjectPreparation
from ..events.outbox import EventWriter, Outbox
from ..jobs.authority import scope_locks
from .device_proof import DevicePublicKey
from .device_store import DeviceStore


class DeviceManagementService:
    def __init__(self, preparation, actor, *, instance, request_id):
        if (not isinstance(preparation, SubjectPreparation) or not isinstance(actor, AuthenticatedPolicyActor)
                or preparation.actor != actor.user_id):
            raise ValueError("actual authenticated own-subject preparation required")
        identifier(request_id)
        self.preparation, self.actor = preparation, actor
        self.instance, self.request_id = instance, request_id
        self.store, self.events = DeviceStore(), EventWriter()

    def _check(self, sql, epoch):
        state, actor = self.preparation.state, self.actor
        for schema, table in ((state.native_schema, "EmailUser"), (state.identity_schema, "profile_profile")):
            sql.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=%s AND table_name=%s", (schema, table))
            if sql.fetchall() != (("InnoDB",),):
                raise ContractError("IDENTITY_UNAVAILABLE", "Device identity storage is unavailable", 503)
        sql.execute("SELECT user,login_id FROM " + state.profiles + " WHERE user=%s OR login_id=%s FOR UPDATE", (actor.native_username, actor.user_id))
        if sql.fetchall() != ((actor.native_username, actor.user_id),):
            raise ContractError("ACCESS_DENIED", "Device identity is unavailable", 403)
        sql.execute("SELECT email,is_active FROM " + state.accounts + " WHERE email=%s FOR UPDATE", (actor.native_username,))
        if sql.fetchall() != ((actor.native_username, 1),):
            raise ContractError("ACCESS_DENIED", "Device account is unavailable", 403)
        current = self.preparation.contexts.current(actor.user_id)
        if current is None or current["context_epoch"] != epoch or state.barrier_active(state.provider, actor.user_id):
            raise ContractError("SUBJECT_UNAVAILABLE", "Device subject changed or expired", 503)

    def _execute(self, effect):
        state = self.preparation.state
        connection = state.connection
        # Reuse the real driver-compatible idle transaction probe; never issue
        # BEGIN over a foreign explicit transaction or project under scope locks.
        Outbox(connection)._require_idle()
        context = self.preparation.prepare(self.actor.user_id)
        scopes = [dict(type="provider", provider=state.provider, external_id=state.provider),
            dict(type="user", provider=state.provider, external_id=self.actor.user_id)]
        with self.preparation.no_refresh_scope(), scope_locks(connection, scopes):
            connection.begin()
            try:
                with connection.cursor() as sql:
                    self._check(sql, context["context_epoch"])
                    result = effect(sql)
                    self._check(sql, context["context_epoch"])
                connection.commit()
            finally:
                connection.rollback()
        return result

    def _audit(self, sql, action, value):
        self.events.append(sql, dict(event_id=str(uuid4()), request_id=self.request_id,
            occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            actor_user_id=self.actor.user_id, actor_kind="user", source="hub", action=action,
            result="succeeded", device_id=value["device_id"], revision=value["revision"]))

    def start_pairing(self, value):
        object_fields(value, ("public_key",))
        key = DevicePublicKey.parse(value["public_key"])
        def effect(sql):
            provider = self.preparation.state.provider
            # An uncertain start can safely request another short challenge for
            # the same still-pending key, never recreate a revoked/active key or
            # extend an old proof. Final confirmation remains one-time.
            pending = self.store.pending_for_key(sql, provider=provider, actor=self.actor.user_id, public_key=key)
            device_id, pairing_id = pending or str(uuid4()), str(uuid4())
            digest = hashlib.sha256(json.dumps(dict(device_id=device_id, pairing_id=pairing_id,
                key_thumbprint=key.thumbprint), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            owner = dict(provider=self.preparation.state.provider, actor=self.actor.user_id, device_id=device_id)
            result = (self.store.create_pending(sql, **owner, public_key=key) if pending is None
                else {key: item for key, item in self.store.status(sql, **owner).items() if key != "key_thumbprint"})
            challenge = self.store.issue(sql, **owner, instance=self.instance, session_id=pairing_id,
                operation="pair", request_sha256=digest)
            self._audit(sql, "device.pair.started", result)
            return dict(**result, key_thumbprint=key.thumbprint, challenge=asdict(challenge))
        return self._execute(effect)

    def status(self, value):
        object_fields(value, ("device_id",))
        return self._execute(lambda sql: self.store.status(sql, provider=self.preparation.state.provider,
            actor=self.actor.user_id, device_id=value["device_id"]))

    def confirm_pairing(self, value):
        object_fields(value, ("device_id", "nonce", "signature"))
        def effect(sql):
            owner = dict(provider=self.preparation.state.provider, actor=self.actor.user_id, device_id=value["device_id"])
            challenge = self.store.pairing_challenge(sql, **owner, nonce=value["nonce"])
            if challenge.instance != self.instance:
                raise ContractError("DEVICE_CONFLICT", "Pairing instance changed", 409)
            result = self.store.consume(sql, provider=owner["provider"], actor=owner["actor"],
                challenge=challenge, signature=value["signature"])
            self._audit(sql, "device.paired", result)
            return result
        return self._execute(effect)

    def revoke(self, value):
        object_fields(value, ("device_id", "revision"))
        revision = sequence(value["revision"])
        def effect(sql):
            result = self.store.revoke(sql, provider=self.preparation.state.provider, actor=self.actor.user_id,
                device_id=value["device_id"], expected_revision=revision)
            if result["revision"] != str(revision):
                self._audit(sql, "device.revoked", result)
            return result
        return self._execute(effect)
