"""Short-lived protected Checkout lease handoff to the *same* paired device.

A new exclusive session stores the browser-authorized Checkout credential only
as AES-GCM ciphertext in a separate table. The existing native session snapshot
remains fingerprint-only, so the seaf-server canonical schema is unchanged.
The holder cannot obtain this secret with the browser URI/ticket alone: Hub
issues it only after a fresh device-key proof and current guarded ACL/Checkout.
It remains retrievable across lost replies until the Agent confirms its journal
has been durably saved, then is cryptographically erased from this table.
"""
import hashlib
import hmac
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..common.errors import ContractError
from ..common.validation import object_fields
from .session_store import conflict

_DOMAIN = b"cloudfile.device-lease-escrow.v1"


def _cipher(secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("Deployment-owned encryption key required")
    return AESGCM(hmac.new(secret, _DOMAIN, hashlib.sha256).digest())


def _aad(instance, session, device, actor):
    return json.dumps([instance, session, device, actor], ensure_ascii=True,
        separators=(",", ":")).encode("ascii")


def encrypt(secret, *, instance, session, device, actor, lease):
    object_fields(lease, ("guard_id", "generation", "credential_epoch",
                          "base_file_id", "token"))
    data = json.dumps(lease, sort_keys=True, ensure_ascii=True,
        separators=(",", ":")).encode("ascii")
    if len(data) > 512:
        raise ValueError("Checkout secret exceeds bounded escrow")
    nonce = secrets.token_bytes(12)
    return nonce + _cipher(secret).encrypt(nonce, data,
        _aad(instance, session, device, actor))


def decrypt(secret, encoded, *, instance, session, device, actor):
    try:
        if not isinstance(encoded, bytes) or not 28 < len(encoded) < 1024:
            raise ValueError()
        value = json.loads(_cipher(secret).decrypt(encoded[:12], encoded[12:],
            _aad(instance, session, device, actor)))
        object_fields(value, ("guard_id", "generation", "credential_epoch",
                              "base_file_id", "token"))
        return value
    except Exception:
        raise ContractError("LOCAL_SESSION_CONFLICT",
            "Device Checkout handoff is unavailable", 409) from None


class CheckoutLeaseEscrow:
    def create(self, sql, *, secret, instance, session, device, actor, lease):
        ciphertext = encrypt(secret, instance=instance, session=session,
            device=device, actor=actor, lease=lease)
        sql.execute(
            "INSERT INTO cf_device_checkout_lease(session_id,ciphertext,expires_at,"
            "created_at) VALUES(%s,%s,FLOOR(UNIX_TIMESTAMP())+600,UTC_TIMESTAMP(6))",
            (session, ciphertext))

    def receive(self, sql, *, secret, instance, session, device, actor,
                expected_digest):
        sql.execute("SELECT ciphertext,acknowledged_at,expires_at "
                    "FROM cf_device_checkout_lease WHERE session_id=%s FOR UPDATE",
                    (session,))
        row = sql.fetchone()
        sql.execute("SELECT FLOOR(UNIX_TIMESTAMP())")
        now = int(sql.fetchone()[0])
        if (row is None or row[1] is not None or now >= row[2]):
            raise conflict()
        value = decrypt(secret, bytes(row[0]), instance=instance,
            session=session, device=device, actor=actor)
        if not hmac.compare_digest(hashlib.sha256(value["token"].encode("ascii")).hexdigest(),
                                   expected_digest):
            raise conflict()
        return value

    def confirm(self, sql, *, session):
        sql.execute("UPDATE cf_device_checkout_lease "
            "SET ciphertext=%s,acknowledged_at=UTC_TIMESTAMP(6) "
            "WHERE session_id=%s AND acknowledged_at IS NULL "
            "AND expires_at>FLOOR(UNIX_TIMESTAMP())", (b"", session))
        if sql.rowcount != 1:
            raise conflict()
