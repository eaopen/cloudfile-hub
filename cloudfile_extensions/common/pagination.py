"""Bounded, expiring cursors tied to actor, filters and authorization generations."""

import base64
import hashlib
import hmac
import json
import re
import time

from .errors import ContractError, invalid


def canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise invalid("Invalid cursor context") from None


def page_size(value=None):
    if value is None:
        return 50
    if type(value) is not int or not 1 <= value <= 100:
        raise invalid("Page size must be between 1 and 100")
    return value


class CursorCodec:
    def __init__(self, secret, *, ttl=300, clock=time.time):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("cursor secret must contain at least 32 bytes")
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError("invalid cursor TTL")
        self._secret = secret
        self._ttl = ttl
        self._clock = clock

    @staticmethod
    def _binding(context):
        return hashlib.sha256(canonical_json(context)).hexdigest()

    def encode(self, marker, *, context, expires_at=None):
        now = int(self._clock())
        expiry = now + self._ttl
        if expires_at is not None:
            expiry = min(expiry, int(expires_at))
        if expiry <= now:
            raise invalid("Cursor context has expired")
        payload = canonical_json({"v": 1, "exp": expiry, "binding": self._binding(context), "marker": marker})
        if len(payload) > 4096:
            raise invalid("Cursor is too large")
        signature = hmac.digest(self._secret, b"cloudfile.cursor.v1\x00" + payload, "sha256")
        return base64.urlsafe_b64encode(signature + payload).rstrip(b"=").decode("ascii")

    def decode(self, token, *, context):
        error = ContractError("INVALID_CURSOR", "Cursor is invalid or expired")
        if not isinstance(token, str) or len(token) > 8192 or not re.fullmatch(r"[A-Za-z0-9_-]+", token):
            raise error
        try:
            blob = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
            signature, payload = blob[:32], blob[32:]
            expected = hmac.digest(self._secret, b"cloudfile.cursor.v1\x00" + payload, "sha256")
            if len(signature) != 32 or not hmac.compare_digest(signature, expected):
                raise error
            value = json.loads(payload)
            if (not isinstance(value, dict) or set(value) != {"v", "exp", "binding", "marker"} or
                    value["v"] != 1 or type(value["exp"]) is not int or
                    value["exp"] <= int(self._clock()) or
                    value["binding"] != self._binding(context)):
                raise error
            return value["marker"]
        except (ValueError, TypeError, UnicodeError):
            raise error from None
