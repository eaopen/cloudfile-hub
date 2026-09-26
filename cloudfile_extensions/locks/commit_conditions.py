"""Internal OIDC lease conditions; no upload, HTTP response or grant cache."""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields, sequence
from ..identity.native_session import SESSION_REFERENCE_KEY
from ..identity.session_authority import OIDCSessionAuthority
from .service import FileLockService


@dataclass(frozen=True)
class NativeLeaseConditions:
    native_username: str = field(repr=False)
    encoded: str = field(repr=False)
    base_version: str

    def for_head(self, head_id):
        """Bind a trusted native Branch head, not a browser-supplied revision.

        This is an internal RPC envelope, not a durable commit receipt. Callers
        must release preparation SQL scopes before submitting and must not
        retry an ambiguous native response as though it proved no publication.
        """
        if not isinstance(head_id, str) or not re.fullmatch(r"[0-9a-f]{40}", head_id):
            raise invalid("Exact native Branch head required")
        conditions = json.loads(self.encoded)
        if set(conditions) != {"path", "context", "scopes", "oidc_session", "lease"}:
            raise invalid("Exact internal lease conditions required")
        conditions["head_id"] = head_id
        encoded = json.dumps(conditions, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 16384:
            raise invalid("Native lease conditions exceed budget")
        return encoded


class OIDCLeaseCommitConditions:
    def __init__(self, service, session_authority):
        if not isinstance(service, FileLockService) or not isinstance(session_authority, OIDCSessionAuthority):
            raise ValueError("actual file lock service and OIDC session authority required")
        self.service, self.session_authority = service, session_authority

    def prepare(self, request, value):
        object_fields(value, ("reference", "resource_uid", "token", "fencing", "base_version"))
        service, resources = self.service, self.service.resources
        ref = service._reference(value["reference"])
        authority = resources.write_authority
        authority.preparation.prepare(authority.actor)
        username = authority.state.username(authority.actor)
        # Release session locks BEFORE resource authorization/native RPC. The
        # native final transaction must independently recheck this exact signed
        # session reference; its scope cannot be borrowed across connections.
        with self.session_authority.guard(request):
            if not request.user.is_authenticated or request.user.username != username:
                raise ContractError("AUTHENTICATION_REQUIRED", "Native lease identity does not match", 401)
            key = request.session.session_key
            session = deepcopy(request.session.get(SESSION_REFERENCE_KEY))
        holder = hmac.digest(resources.store.secret, json.dumps([
            "cf.lock.holder.v1", authority.state.provider, authority.actor, key],
            ensure_ascii=False, separators=(",", ":")).encode("utf-8"), "sha256").hex()
        if not hmac.compare_digest(holder, service.holder):
            raise ContractError("LOCK_CONFLICT", "Lease belongs to another authenticated session", 409)
        token = value["token"]
        service.leases._holder(authority.actor, holder, token, 600)
        fence = sequence(value["fencing"])
        if not 1 <= fence <= 2 ** 64 - 1 or not isinstance(value["base_version"], str) or not re.fullmatch(r"[0-9a-f]{40}", value["base_version"]):
            raise invalid("Exact native lease version/fencing required")
        def inspect(sql, reference):
            evidence, row = service._resource(sql, reference)
            if row is None or row["uid"] != value["resource_uid"]:
                raise ContractError("LOCK_CONFLICT", "Resource lifecycle changed", 409)
            lease = service.leases._load(sql, row["uid"], reference["repo_id"])
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
            if (lease is None or not lease[7] or lease[1] != fence or lease[2] != authority.actor or
                    lease[3] != holder or not hmac.compare_digest(lease[4], digest) or lease[5] != value["base_version"]):
                raise ContractError("LOCK_CONFLICT", "Lease is no longer current", 409)
            if service.version_reader(sql, reference, evidence) != value["base_version"]:
                raise ContractError("RESOURCE_VERSION_CONFLICT", "Native file content changed", 409)
            current = authority.preparation.contexts.current(authority.actor)
            if current is None:
                raise ContractError("SUBJECT_UNAVAILABLE", "Current lease subject is unavailable", 503)
            provider = authority.state.provider
            oidc_provider = "cf_oidc_" + session["scope_hash"][:24]
            conditions = dict(path=reference["path"],
                context=dict(provider=provider, userId=authority.actor, epoch=current["context_epoch"]),
                scopes=[dict(type="provider", provider=provider, external_id=provider),
                    dict(type="provider", provider=oidc_provider, external_id=oidc_provider),
                    dict(type="user", provider=provider, external_id=authority.actor),
                    dict(type="repo", provider="cloudfile", external_id=reference["repo_id"])],
                oidc_session=dict(session, session_key=key),
                lease=dict(resource_uid=row["uid"], holder_id=holder, token=token,
                    fencing=str(fence), base_version=value["base_version"]))
            encoded = json.dumps(conditions, ensure_ascii=False, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > 16384:
                raise invalid("Native lease conditions exceed budget")
            return NativeLeaseConditions(username, encoded, value["base_version"])
        # Produces conditions only. NEVER call a separately locking RPC inside
        # consume; its caller must release SQL scopes before native submission.
        # The Server repeats every actual condition at final publication.
        return authority.consume(ref, inspect)
