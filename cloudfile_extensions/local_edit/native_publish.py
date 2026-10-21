"""Shared Hub -> existing Seafile native conditional single-file publication.

This is a *transport adapter*, NOT a new Seafile file engine or a grant.
The native file index, Block Store, lock barrier and atomic Branch CAS remain
the sole publishing authority. Caller-owned OIDC/device checks are not merged.
"""
import json
import re
import time

from ..common.errors import ContractError, invalid

_HEX40 = re.compile(r"^[0-9a-f]{40}$")

_FULL_METHODS = {
    "web": "seafile_cloudfile_put_file_with_barriers",
    "optimistic": "seafile_cloudfile_put_file_with_barriers",
    "exclusive": "seafile_cloudfile_publish_edit",
}


def native_head(response):
    """Parse the Seafile repo HEAD using an exact, backward-compatible key."""
    if not isinstance(response, dict):
        raise ContractError("EDIT_UNAVAILABLE", "Seafile native repository unavailable", 503)
    keys = [key for key in ("head_cmmt_id", "head-cmmt-id") if key in response]
    if len(keys) != 1 or not isinstance(response[keys[0]], str) or (
            not _HEX40.fullmatch(response[keys[0]])):
        raise ContractError("EDIT_UNAVAILABLE", "Current native repository head unavailable", 503)
    return response[keys[0]]


def current_native_head(repo, *, call, now=time.monotonic):
    return native_head(call("seafile_get_repo", (repo,), now() + 5))


def native_target(path):
    """Use already authorized original cloud target, never client workcopy name.

    Seafile's normalize_utf8_path()/format_dir_path() remains responsible for
    definitive path canonicalization, existence and reserved-name handling.
    """
    if (not isinstance(path, str) or not path.startswith("/") or
            len(path.encode("utf-8")) > 4096 or "\x00" in path or
            path.endswith("/") or "//" in path):
        raise invalid("One original cloud file target required")
    parent, separator, filename = path.rpartition("/")
    if not separator or not filename or filename in (".", ".."):
        raise invalid("Original cloud file target invalid")
    return parent or "/", filename


def full_native_publish(*, call, repo, staged, user, condition,
                        mode, target_path=None, head=None, timeout=180, now=time.monotonic):
    """Run one existing Seafile RPC with a mode-specific authoritative condition.

    The caller MUST re-read the durable Intent after an unknown Agent result.
    Web uses its explicitly selected HEAD and never silently refreshes it.
    """
    if mode not in _FULL_METHODS:
        raise ValueError("Explicit Web/ordinary/Checkout publisher required")
    if (not isinstance(condition, dict) or
            not isinstance(repo, str) or not repo or
            not isinstance(user, str) or not user or
            not isinstance(staged, str) or not staged):
        raise invalid("Original authorized native publication required")
    # Web's legacy condition intentionally has no path: Seafile's own
    # put_file_rpc constructs and verifies it before Branch publication.
    # Never add path to the Web condition: its strict RPC field count is
    # part of the deployed Seafile/CloudFile protocol.
    original = condition.get("path")
    if mode != "web" and not isinstance(original, str):
        raise invalid("Device original cloud target missing")
    if original is not None and target_path is not None and original != target_path:
        raise invalid("Authorized cloud target does not match native target")
    path = target_path if target_path is not None else original
    parent, filename = native_target(path)
    if mode == "web":
        if ("oidc_session" not in condition or
                "agent_upload" in condition or "editing" in condition):
            raise invalid("Web OIDC publication condition required")
        expected = head
    elif mode == "optimistic":
        if ("agent_upload" not in condition or "expected_file_id" not in condition or
                "editing" in condition or "oidc_session" in condition or
                "local_commit" in condition):
            raise invalid("Original optimistic device write condition required")
        expected = current_native_head(repo, call=call, now=now)
    else:
        if ("editing" not in condition or
                ("local_commit" not in condition and "oidc_session" not in condition) or
                "agent_upload" in condition):
            raise invalid("Current Checkout CommitIntent required")
        expected = current_native_head(repo, call=call, now=now)
    if not isinstance(expected, str) or not _HEX40.fullmatch(expected):
        raise invalid("Explicit repository HEAD required")
    publish_condition = dict(condition, head_id=expected) if mode != "web" else condition
    if mode == "web" and condition.get("head_id") != head:
        raise invalid("Web selected head cannot be silently changed")
    result = call(_FULL_METHODS[mode],
                  (repo, staged, parent, filename, user,
                   json.dumps(publish_condition, separators=(",", ":"))),
                  now() + timeout)
    if not isinstance(result, str) or not _HEX40.fullmatch(result):
        raise ContractError("PUBLICATION_UNCONFIRMED",
                            "Native publication reply unconfirmed", 503)
    return result


_CDC_METHODS = {
    "optimistic": "seafile_cloudfile_publish_optimistic_blocks",
    "exclusive": "seafile_cloudfile_publish_edit_blocks",
}


def cdc_native_publish(*, call, repo, ordered, size, user, condition,
                       mode, head, timeout=240, now=time.monotonic):
    """Use Seafile's existing ordered Block Store and native Branch CAS.

    Web intentionally has no CDC entry in v0.7; the two signed Agent modes
    retain different native authorization conditions and durable Intent tables.
    """
    if mode not in _CDC_METHODS or not isinstance(condition, dict):
        raise invalid("Guarded Agent CDC mode and condition required")
    if (mode == "optimistic" and
            ("agent_upload" not in condition or "expected_file_id" not in condition or
             "editing" in condition or "oidc_session" in condition)):
        raise invalid("Original optimistic CDC session required")
    if (mode == "exclusive" and
            ("editing" not in condition or
             ("local_commit" not in condition and "oidc_session" not in condition) or
             "agent_upload" in condition)):
        raise invalid("Current Checkout CDC Intent required")
    if not isinstance(head, str) or not _HEX40.fullmatch(head):
        raise invalid("Current Seafile native head required")
    if (not isinstance(ordered, list) or not 1 <= len(ordered) <= 64 or
            any(not isinstance(item, str) or not _HEX40.fullmatch(item)
                for item in ordered) or type(size) is not int or
            not 1 <= size <= 128 * 1024 * 1024):
        raise invalid("Original bounded ordered Seafile blocks required")
    parent, filename = native_target(condition.get("path"))
    args = (repo, json.dumps(ordered, separators=(",", ":")), str(size),
            parent, filename, user,
            json.dumps(dict(condition, head_id=head), separators=(",", ":")))
    result = call(_CDC_METHODS[mode], args, now() + timeout)
    if not isinstance(result, str) or not _HEX40.fullmatch(result):
        raise ContractError("PUBLICATION_UNCONFIRMED",
                            "Native Seafile block publication unconfirmed", 503)
    return result
