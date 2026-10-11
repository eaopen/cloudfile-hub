"""Derive stable, secret Web-Checkout proof for an idempotent OIDC request.
Never exposed in a browser URL, LocalSession snapshot or response.
"""
import hashlib
import hmac
import json

def deterministic_checkout_token(secret, *, provider, actor, holder, reference,
                                  device_id, base_file_id, request_key):
    """Stable on a same-session retry; never returned to the browser/URI."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("Current server secret required")
    payload = json.dumps(["cloudfile.exclusive-checkout.v1", provider, actor,
        holder, reference, device_id, base_file_id, request_key],
        sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()
