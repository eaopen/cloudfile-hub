# -*- coding: utf-8 -*-
"""Django-free callback identity helpers."""

import hashlib
import json


def dedupe_key(payload):
    """Best-effort completion cache key, not a durable publication identity."""
    value = '\x1f'.join((
        str(payload.get('key', '')),
        str(payload.get('status', '')),
        str(payload.get('url', '')),
    ))
    return 'cloudfile_onlyoffice_completed_' + hashlib.sha256(
        value.encode('utf-8')).hexdigest()


def signed_payload_matches(claims, payload):
    """Bind the callback body to signed claims (body-token or header JWT)."""
    if not isinstance(claims, dict) or not isinstance(payload, dict):
        return False
    signed = claims.get("payload", claims)
    if not isinstance(signed, dict):
        return False
    unsigned = {key: value for key, value in payload.items() if key != "token"}
    if not unsigned or any(key not in signed for key in unsigned):
        return False
    # Python equality treats True as 1; callback status and nested values must
    # match signed JSON types as well as values.
    try:
        def encode(value):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return encode(unsigned) == encode({key: signed[key] for key in unsigned})
    except (TypeError, ValueError):
        return False
