"""Short-lived encrypted upload selectors, never native publication authority."""
import base64
import hashlib
import hmac
import json
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..common.errors import ContractError
from ..migration.native_status import _object

UPLOAD_PATH = "/api/v2.1/cloudfile/extensions/local-edit/v1/agent/commit-upload/"
AAD = b"cloudfile.device-upload.v1"


def _cipher(secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("owned deployment secret required")
    return AESGCM(hmac.new(secret, AAD, hashlib.sha256).digest())


def seal(secret, value, *, now=None):
    now = int(time.time()) if now is None else now
    raw = json.dumps(dict(value=value, issued=now, expires=now + 60),
        separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 10000:
        raise ValueError("upload grant exceeds budget")
    nonce = secrets.token_bytes(12)
    return "v1." + base64.urlsafe_b64encode(nonce + _cipher(secret).encrypt(nonce, raw, AAD)).decode().rstrip("=")


def unseal(secret, token, *, now=None):
    try:
        if not isinstance(token, str) or not 40 <= len(token) <= 14000 or not token.startswith("v1."):
            raise ValueError()
        encoded = token[3:]
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded:
            raise ValueError()
        value = json.loads(_cipher(secret).decrypt(raw[:12], raw[12:], AAD), object_pairs_hook=_object)
        now = int(time.time()) if now is None else now
        if (set(value) != {"value", "issued", "expires"} or
                type(value["issued"]) is not int or type(value["expires"]) is not int or
                value["expires"] - value["issued"] != 60 or
                not value["issued"] <= now < value["expires"]):
            raise ValueError()
        return value["value"]
    except Exception:
        raise ContractError("AUTHENTICATION_REQUIRED", "Upload credential is invalid or expired", 401) from None
