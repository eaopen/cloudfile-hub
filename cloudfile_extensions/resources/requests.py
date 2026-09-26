"""Same-transaction durable resource retries; no authority or lifecycle grant."""
import hashlib
import hmac
import json
import re

from ..authorization.requests import require_storage, _pairs
from ..common.errors import ContractError, invalid


def execute(cursor, *, provider, actor, operation, key, request, lifecycle, secret, mutate):
    if not isinstance(key, str) or not re.fullmatch(r"[\x21-\x7e]{1,128}", key):
        raise invalid("Invalid resource idempotency key")
    def packed(value):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    identity = hashlib.sha256(packed(["resource.v1", provider, actor, key]).encode()).hexdigest()
    digest = hashlib.sha256(packed([operation, request, lifecycle]).encode()).hexdigest()
    require_storage(cursor)
    cursor.execute("SELECT request_digest,result_json,inherited_effect FROM cf_policy_request WHERE request_key=%s FOR UPDATE", (identity,))
    rows = cursor.fetchall()
    if len(rows) > 1:
        raise ValueError("duplicate resource retry record")
    if rows:
        prior_digest, saved, effect = rows[0]
        if prior_digest != digest:
            raise ContractError("IDEMPOTENCY_CONFLICT", "Resource request or lifecycle has changed", 409)
        if effect != 0 or not isinstance(saved, str) or len(saved.encode()) > 60000:
            raise ValueError("invalid resource retry record")
        envelope = json.loads(saved, object_pairs_hook=_pairs)
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError("invalid resource retry envelope")
        payload = envelope["payload"]
        signed = packed([identity, digest, payload]).encode()
        expected = hmac.digest(secret, signed, "sha256").hex()
        if not isinstance(envelope["signature"], str) or not hmac.compare_digest(envelope["signature"], expected):
            raise ValueError("invalid resource retry integrity")
        if not isinstance(payload, list) or len(payload) != 2 or not isinstance(payload[0], dict) or type(payload[1]) is not bool:
            raise ValueError("invalid resource retry result")
        return payload[0], payload[1]
    result = mutate()
    if not isinstance(result, tuple) or len(result) != 2 or not isinstance(result[0], dict) or type(result[1]) is not bool:
        raise ValueError("invalid resource mutation result")
    payload = list(result)
    signature = hmac.digest(secret, packed([identity, digest, payload]).encode(), "sha256").hex()
    saved = packed(dict(payload=payload, signature=signature))
    if len(saved.encode()) > 60000:
        raise ContractError("RESPONSE_TOO_LARGE", "Resource retry response exceeds the limit", 413)
    cursor.execute("INSERT INTO cf_policy_request(request_key,request_digest,result_json,inherited_effect,created_at) VALUES(%s,%s,%s,0,UTC_TIMESTAMP(6))", (identity, digest, saved))
    return result
