"""Exact signed Agent2 single-file CommitIntent request vocabulary.

Proofs bind an existing guarded Checkout, immutable snapshot digest, device,
session revision and intent. This is a DEVICE WRITE PREPARE contract, NOT
permission to upload arbitrary bytes or publish a Seafile file. Native Branch
publication remains a separate server-authorized final transaction.
"""
import hashlib
import hmac
import json
import re

from ..common.validation import object_fields
from ..common.errors import ContractError
from .device_proof import _uuid

MAX_MANUAL_BYTES = 128 * 1024 * 1024


def validate_request(value, *, signed=False):
    names = ("session_id", "device_id", "intent_id", "guard_id", "generation",
        "credential_epoch", "token", "base_file_id", "content_digest",
        "snapshot_size", "action")
    object_fields(value, names + (("challenge", "signature") if signed else ()))
    for name in ("session_id", "device_id", "intent_id", "guard_id"):
        _uuid(value[name])
    for name in ("generation", "credential_epoch"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value[name]):
            raise ValueError("canonical credential epoch/generation required")
    if (not isinstance(value["token"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["token"]) or
            not isinstance(value["base_file_id"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["base_file_id"]) or
            not isinstance(value["content_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["content_digest"]) or
            type(value["snapshot_size"]) is not int or not 0 <= value["snapshot_size"] <= MAX_MANUAL_BYTES or
            value["action"] not in ("commit", "checkin")):
        raise ValueError("bounded manually captured one-file commit required")
    return value


def bind_request(value, *, snapshot, session_row, edit_guard, current_native):
    """Produce only a digest; never return the bearer credential to the Agent.

    Caller MUST have already entered the actual current resource write
    authority and checked latest native Branch/base and file identity.
    """
    if (snapshot["mode"] != "exclusive-edit" or not isinstance(snapshot.get("lease"), dict) or
            snapshot["lease"].get("fencing") != value["generation"] or
            edit_guard["mode"] != "checkout" or not edit_guard["credential_active"] or
            edit_guard["owner_native_user"] != current_native or
            edit_guard["guard_id"] != value["guard_id"] or
            str(edit_guard["generation"]) != value["generation"] or
            str(edit_guard["credential_epoch"]) != value["credential_epoch"] or
            edit_guard["base_file_id"] != value["base_file_id"] or
            edit_guard["pending_intent"] not in (None, value["intent_id"]) or
            not hmac.compare_digest(edit_guard["proof_digest"],
                hashlib.sha256(value["token"].encode("ascii")).hexdigest()) or
            not hmac.compare_digest(snapshot["lease"]["token_digest"],
                edit_guard["proof_digest"])):
        raise ContractError("EDIT_CONFLICT", "Active device Checkout is required", 409)
    protected = [
        "cloudfile.commit.v1", value["session_id"], value["device_id"],
        str(session_row[3]), str(session_row[9]), snapshot["resource_uid"],
        snapshot["resource"]["repo_id"], snapshot["resource"]["path"],
        value["guard_id"], value["generation"], value["credential_epoch"],
        value["base_file_id"], value["intent_id"], value["content_digest"],
        value["snapshot_size"], value["action"],
    ]
    message = json.dumps(protected, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(message).hexdigest()
