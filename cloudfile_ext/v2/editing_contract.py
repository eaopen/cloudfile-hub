"""CF-EDIT V2 protocol values shared by Agent2 and external PLM/CAD callers.

This module has no HTTP, Django, or Seafile dependency. The authenticated
principal is supplied by a trusted adapter, never copied from request JSON.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
import posixpath
import re
from uuid import UUID


class EditConflict(ValueError):
    pass


class EditDenied(ValueError):
    pass


def _text(value, maximum, name):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("invalid " + name)
    return value


def uuid(value):
    value = _text(value, 36, "UUID")
    try:
        if str(UUID(value)) != value:
            raise ValueError("noncanonical UUID")
    except (ValueError, AttributeError) as exc:
        raise ValueError("invalid UUID") from exc
    return value


def object_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise ValueError("invalid native Seafile File ID")
    return value


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("invalid SHA-256")
    return value


def reference(repo_id, path):
    uuid(repo_id)
    path = _text(path, 4096, "file path")
    if (not path.startswith("/") or path == "/" or "\\" in path or
            path.endswith("/") or "//" in path or posixpath.normpath(path) != path
            or len(path.encode("utf-8")) > 4096):
        raise ValueError("noncanonical file path")
    return hashlib.sha256(path.encode("utf-8")).digest()


@dataclass(frozen=True)
class Principal:
    """Values come from current CloudFile identity and effective ACL."""
    uid: str
    native_user: str
    client_type: str
    client_id: str

    def __post_init__(self):
        _text(self.uid, 225, "stable UID")
        _text(self.native_user, 255, "native Seafile username")
        if self.client_type not in ("agent", "integration", "web"):
            raise ValueError("invalid client type")
        _text(self.client_id, 128, "client identity")


@dataclass(frozen=True)
class GuardProof:
    guard_id: str
    generation: int
    credential_epoch: int
    token: str

    def __post_init__(self):
        uuid(self.guard_id)
        if (type(self.generation) is not int or not 1 <= self.generation < 2**64
                or type(self.credential_epoch) is not int
                or not 1 <= self.credential_epoch < 2**64):
            raise ValueError("invalid edit fencing numbers")
        digest(self.token)

    @property
    def token_digest(self):
        return hashlib.sha256(self.token.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class CommitRequest:
    intent_id: str
    action: str
    expected_file_id: str
    staged_file_id: str
    content_digest: str

    def __post_init__(self):
        uuid(self.intent_id)
        if self.action not in ("optimistic", "commit", "checkin", "checkin-unchanged"):
            raise ValueError("invalid commit action")
        object_id(self.expected_file_id)
        object_id(self.staged_file_id)
        digest(self.content_digest)
        if self.action == "checkin-unchanged":
            if self.expected_file_id != self.staged_file_id:
                raise ValueError("unchanged Checkin must preserve File ID")
            if self.content_digest != hashlib.sha256(b"").hexdigest():
                raise ValueError("unchanged Checkin must have empty payload digest")

    def request_digest(self, repo_id, path, principal, proof):
        path_hash = reference(repo_id, path)
        if (self.action == "optimistic") != (proof is None):
            raise ValueError("optimistic edit cannot carry Guard credentials")
        payload = dict(
            repo_id=repo_id, path=path, path_hash=path_hash.hex(),
            actor_uid=principal.uid, action=self.action,
            expected_file_id=self.expected_file_id,
            staged_file_id=self.staged_file_id,
            content_digest=self.content_digest,
            guard_id=proof.guard_id if proof else None,
            generation=proof.generation if proof else None,
            credential_epoch=proof.credential_epoch if proof else None,
        )
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


def verify_proof(row, principal, proof, *, allow_expired=False):
    """Compare secrets in constant time. Must be called on an SQL-locked row."""
    if (row["guard_id"] != proof.guard_id or
            row["generation"] != proof.generation or
            row["credential_epoch"] != proof.credential_epoch or
            row["owner_uid"] != principal.uid or
            row["owner_native_user"] != principal.native_user or
            row["client_type"] != principal.client_type or
            row["client_id"] != principal.client_id or
            not hmac.compare_digest(row["proof_digest"] or "", proof.token_digest)):
        raise EditDenied("stale or unauthorized editing credential")
    # A matching expired credential can ONLY cancel a prepared intent or
    # release a failed Checkout. All publish/renew/resume calls require live.
    if not allow_expired and not row["active"]:
        raise EditConflict("Checkout is expired; never revive old credentials")


def public_guard(row):
    if not row or not row["guard_id"]:
        return {"active": False}
    return {
        "active": bool(row["active"]),
        "guard_id": row["guard_id"],
        "generation": str(row["generation"]),
        "mode": row["mode"],
        "owner_uid": row["owner_uid"],
        "client_type": row["client_type"],
        "checkout_policy": row["checkout_policy"],
        "lease_expires_at": row["lease_expires_at"].isoformat() + "Z" if row["lease_expires_at"] else None,
    }
