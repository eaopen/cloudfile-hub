"""P-256 device possession only; never file, user or session authorization.

The authenticated pairing flow stores the canonical public key. A subsequent
consumer must load that key and its current revocation state from authoritative
storage and consume its server-issued challenge once in the same guarded
transaction. A successful signature alone is deliberately insufficient.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
import re
from uuid import UUID
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..common.errors import ContractError


P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
OPERATIONS = frozenset({"pair", "claim", "read", "renew", "commit", "cancel"})


def rejected():
    return ContractError("DEVICE_PROOF_INVALID", "Device possession proof is invalid", 401)


def _decode(value, size):
    if (not isinstance(value, str) or len(value) != (size * 8 + 5) // 6 or
            not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        raise ValueError()
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != size or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise ValueError()
    return raw


def _uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError()
    return value


@dataclass(frozen=True)
class DevicePublicKey:
    """Public registration value only, never a caller-selected verification key."""
    x: str
    y: str

    @classmethod
    def parse(cls, value):
        try:
            if not isinstance(value, dict) or set(value) != {"kty", "crv", "x", "y"}:
                raise ValueError()
            if value["kty"] != "EC" or value["crv"] != "P-256":
                raise ValueError()
            result = cls(value["x"], value["y"])
            result.native_key()  # Reject off-curve and invalid coordinates.
            return result
        except (ValueError, TypeError, KeyError, OverflowError):
            raise rejected() from None

    def native_key(self):
        return ec.EllipticCurvePublicNumbers(int.from_bytes(_decode(self.x, 32), "big"),
            int.from_bytes(_decode(self.y, 32), "big"), ec.SECP256R1()).public_key()

    @property
    def jwk(self):
        return dict(kty="EC", crv="P-256", x=self.x, y=self.y)

    @property
    def thumbprint(self):
        # RFC 7638 member ordering/UTF-8; public key only, no private parameters.
        raw = json.dumps(self.jwk, sort_keys=True, separators=(",", ":")).encode("ascii")
        return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


@dataclass(frozen=True)
class DeviceChallenge:
    instance: str
    device_id: str
    session_id: str
    operation: str
    nonce: str
    issued_at: int
    expires_at: int
    request_sha256: str

    def message(self):
        """Server-owned canonical bytes; not reconstructed from Agent claims.

        request_sha256 binds the exact validated operation payload, including
        staged content digest/base/fencing for commit. The later consumer owns
        that actual request hash; a browser-supplied expected hash is not proof.
        Pair uses a server-generated pairing session UUID, not an edit session.
        """
        parsed = urlsplit(self.instance)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
                parsed.query or parsed.fragment or parsed.path not in ("", "/") or
                self.instance.endswith("/") or any(ord(c) < 33 or ord(c) > 126 for c in self.instance)):
            raise ValueError("fixed canonical HTTPS instance origin required")
        if "%" in self.instance or "\\" in self.instance or parsed.netloc != parsed.netloc.lower():
            raise ValueError("fixed canonical HTTPS instance origin required")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("fixed canonical HTTPS instance origin required")
        _uuid(self.device_id)
        _uuid(self.session_id)
        if (self.operation not in OPERATIONS or type(self.issued_at) is not int or
                type(self.expires_at) is not int or not 0 <= self.issued_at <= 2 ** 53 - 1 or
                not self.issued_at < self.expires_at <= self.issued_at + 120 or
                self.expires_at > 2 ** 53 - 1 or not isinstance(self.request_sha256, str) or
                not re.fullmatch(r"[0-9a-f]{64}", self.request_sha256)):
            raise ValueError("fixed bounded server challenge required")
        _decode(self.nonce, 32)
        payload = dict(v=1, instance=self.instance, device_id=self.device_id,
            session_id=self.session_id, operation=self.operation, nonce=self.nonce,
            issued_at=self.issued_at, expires_at=self.expires_at, request_sha256=self.request_sha256)
        return b"cloudfile.device-proof.v1\n" + json.dumps(payload, sort_keys=True,
            ensure_ascii=True, separators=(",", ":")).encode("ascii")


def verify_possession(public_key, challenge, signature, *, now):
    """Verify fixed raw IEEE P1363 r||s signature, not DER/JWT/Agent JSON.

    Raises on failure and returns no identity/grant. ``now`` is captured from
    trusted server time, never a client timestamp. Challenge consumption and
    device revocation/current permissions MUST be checked again before effects.
    """
    try:
        if not isinstance(public_key, DevicePublicKey) or not isinstance(challenge, DeviceChallenge):
            raise ValueError()
        message = challenge.message()
        if type(now) is not int or not challenge.issued_at <= now < challenge.expires_at:
            raise ValueError()
        raw = _decode(signature, 64)
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        if not 0 < r < P256_ORDER or not 0 < s < P256_ORDER:
            raise ValueError()
        public_key.native_key().verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, OverflowError, InvalidSignature, AttributeError):
        raise rejected() from None
