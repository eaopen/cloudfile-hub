"""Device persistence under caller-owned current identity/subject transaction.

Not an HTTP authenticator: the real browser/current-user authority must establish
provider/actor and hold provider/user coordination through commit. Agent calls
also need actual user/file/session authorization; a device proof grants none.
No commit/rollback, automatic DDL or standalone boolean authorization callback.
"""
import base64
import hashlib
import secrets
from uuid import UUID

from ..common.errors import ContractError
from ..common.validation import identifier
from .device_proof import DeviceChallenge, DevicePublicKey, verify_possession
from .device_storage import require_storage


def conflict():
    return ContractError("DEVICE_CONFLICT", "Device state or proof changed", 409)


class DeviceStore:
    def pending_for_key(self, sql, *, provider, actor, public_key):
        sql.execute("SELECT device_id FROM cf_local_device WHERE provider=%s AND owner_user_id=%s AND key_thumbprint=%s FOR UPDATE", (provider, actor, public_key.thumbprint))
        rows = sql.fetchall()
        if len(rows) > 1:
            raise conflict()
        if not rows:
            return None
        self._scope(sql, provider, actor, rows[0][0])
        key, state, _ = self._load(sql, provider, actor, rows[0][0])
        if state != "pending" or key != public_key:
            raise conflict()
        return rows[0][0]

    def status(self, sql, *, provider, actor, device_id):
        self._scope(sql, provider, actor, device_id)
        key, state, revision = self._load(sql, provider, actor, device_id)
        return dict(device_id=device_id, state=state, revision=str(revision), key_thumbprint=key.thumbprint)

    @staticmethod
    def _scope(sql, provider, actor, device_id):
        identifier(provider, maximum=32)
        identifier(actor, maximum=225)
        if not isinstance(device_id, str) or str(UUID(device_id)) != device_id:
            raise ValueError("canonical device required")
        # RELEASE fails outside a real transaction. This is not a grant, only
        # proof that persistence belongs to the caller's existing SQL scope.
        point = "cf_device_" + secrets.token_hex(8)
        sql.execute("SAVEPOINT " + point)
        sql.execute("RELEASE SAVEPOINT " + point)
        require_storage(sql)

    @staticmethod
    def _load(sql, provider, actor, device_id):
        sql.execute("SELECT provider,owner_user_id,key_x,key_y,key_thumbprint,state,revision FROM cf_local_device WHERE device_id=%s FOR UPDATE", (device_id,))
        row = sql.fetchone()
        if row is None or row[:2] != (provider, actor):
            raise ContractError("ACCESS_DENIED", "Device is not available", 403)
        if (len(row) != 7 or row[5] not in {"pending", "active", "revoked"} or
                type(row[6]) is not int or not 1 <= row[6] <= 2 ** 64 - 1):
            raise ContractError("DEVICE_STATE_PENDING", "Device storage requires reconciliation", 503)
        key = DevicePublicKey.parse(dict(kty="EC", crv="P-256", x=row[2], y=row[3]))
        if key.thumbprint != row[4]:
            raise ContractError("DEVICE_STATE_PENDING", "Device storage requires reconciliation", 503)
        return key, row[5], row[6]

    def create_pending(self, sql, *, provider, actor, device_id, public_key):
        self._scope(sql, provider, actor, device_id)
        if not isinstance(public_key, DevicePublicKey):
            raise ValueError("validated public key required")
        key = DevicePublicKey.parse(public_key.jwk)
        sql.execute("SELECT COUNT(*) FROM cf_local_device WHERE provider=%s AND owner_user_id=%s AND state IN ('pending','active')", (provider, actor))
        if sql.fetchone()[0] >= 32:
            raise ContractError("DEVICE_LIMIT", "Device limit reached", 409)
        sql.execute("SELECT device_id FROM cf_local_device WHERE device_id=%s OR (provider=%s AND owner_user_id=%s AND key_thumbprint=%s) FOR UPDATE", (device_id, provider, actor, key.thumbprint))
        if sql.fetchone() is not None:
            raise conflict()
        sql.execute("INSERT INTO cf_local_device(device_id,provider,owner_user_id,key_x,key_y,key_thumbprint,state,revision,updated_at) VALUES(%s,%s,%s,%s,%s,%s,'pending',1,UTC_TIMESTAMP(6))", (device_id, provider, actor, key.x, key.y, key.thumbprint))
        return dict(device_id=device_id, state="pending", revision="1")

    def issue(self, sql, *, provider, actor, device_id, instance, session_id, operation, request_sha256):
        self._scope(sql, provider, actor, device_id)
        _, state, revision = self._load(sql, provider, actor, device_id)
        if state != ("pending" if operation == "pair" else "active"):
            raise conflict()
        sql.execute("SELECT FLOOR(UNIX_TIMESTAMP())")
        now = int(sql.fetchone()[0])
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        challenge = DeviceChallenge(instance, device_id, session_id, operation, nonce, now, now + 60, request_sha256)
        challenge.message()
        if len(instance) > 255:
            raise ValueError("bounded instance origin required")
        sql.execute("SELECT COUNT(*) FROM cf_local_device_challenge WHERE device_id=%s AND expires_at>%s AND consumed_at IS NULL", (device_id, now))
        if sql.fetchone()[0] >= 32:
            raise ContractError("DEVICE_CHALLENGE_LIMIT", "Pending device challenge limit reached", 409)
        digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        sql.execute("INSERT INTO cf_local_device_challenge(nonce_digest,device_id,device_revision,instance,session_id,operation,request_sha256,issued_at,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (digest, device_id, revision, instance, session_id, operation, request_sha256, now, now + 60))
        return challenge

    def verify_saved(self, sql, *, provider, actor, challenge, signature):
        if not isinstance(challenge, DeviceChallenge):
            raise ValueError("actual saved server challenge required")
        challenge.message()
        self._scope(sql, provider, actor, challenge.device_id)
        key, state, revision = self._load(sql, provider, actor, challenge.device_id)
        if state != ("pending" if challenge.operation == "pair" else "active"):
            raise conflict()
        digest = hashlib.sha256(challenge.nonce.encode("ascii")).hexdigest()
        sql.execute("SELECT device_id,device_revision,instance,session_id,operation,request_sha256,issued_at,expires_at,consumed_at FROM cf_local_device_challenge WHERE nonce_digest=%s FOR UPDATE", (digest,))
        row = sql.fetchone()
        expected = (challenge.device_id, revision, challenge.instance, challenge.session_id,
            challenge.operation, challenge.request_sha256, challenge.issued_at, challenge.expires_at, None)
        if row != expected:
            raise conflict()
        sql.execute("SELECT FLOOR(UNIX_TIMESTAMP())")
        verify_possession(key, challenge, signature, now=int(sql.fetchone()[0]))
        return revision

    def consume(self, sql, *, provider, actor, challenge, signature):
        revision = self.verify_saved(sql, provider=provider, actor=actor, challenge=challenge, signature=signature)
        digest = hashlib.sha256(challenge.nonce.encode("ascii")).hexdigest()
        # Repeat expiry at the actual conditional consumption statement, not
        # only before cryptography. Revocation uses this same locked device row.
        sql.execute("UPDATE cf_local_device_challenge SET consumed_at=UTC_TIMESTAMP(6) WHERE nonce_digest=%s AND consumed_at IS NULL AND expires_at>FLOOR(UNIX_TIMESTAMP())", (digest,))
        if sql.rowcount != 1:
            raise conflict()
        if challenge.operation == "pair":
            if revision == 2 ** 64 - 1:
                raise conflict()
            sql.execute("UPDATE cf_local_device SET state='active',revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE device_id=%s AND state='pending' AND revision=%s", (challenge.device_id, revision))
            if sql.rowcount != 1:
                raise conflict()
            revision += 1
        return dict(device_id=challenge.device_id, state="active", revision=str(revision))

    def pairing_challenge(self, sql, *, provider, actor, device_id, nonce):
        # Caller supplies only the proof selector, not an expected operation,
        # request digest, origin, revision or timestamp to authenticate against.
        self._scope(sql, provider, actor, device_id)
        _, state, _ = self._load(sql, provider, actor, device_id)
        if state != "pending" or not isinstance(nonce, str) or len(nonce) != 43:
            raise conflict()
        digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        sql.execute("SELECT instance,session_id,operation,request_sha256,issued_at,expires_at,consumed_at FROM cf_local_device_challenge WHERE nonce_digest=%s AND device_id=%s FOR UPDATE", (digest, device_id))
        row = sql.fetchone()
        if row is None or row[2] != "pair" or row[6] is not None:
            raise conflict()
        challenge = DeviceChallenge(row[0], device_id, row[1], row[2], nonce, row[4], row[5], row[3])
        challenge.message()
        return challenge

    def revoke(self, sql, *, provider, actor, device_id, expected_revision):
        self._scope(sql, provider, actor, device_id)
        _, state, revision = self._load(sql, provider, actor, device_id)
        if type(expected_revision) is not int or expected_revision != revision or revision == 2 ** 64 - 1:
            raise conflict()
        if state != "revoked":
            sql.execute("UPDATE cf_local_device SET state='revoked',revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE device_id=%s AND revision=%s", (device_id, revision))
            if sql.rowcount != 1:
                raise conflict()
            revision += 1
        # Do not delete/reset key identity or revision; every older challenge
        # fails its device state/revision check, even if its expiry is future.
        return dict(device_id=device_id, state="revoked", revision=str(revision))
