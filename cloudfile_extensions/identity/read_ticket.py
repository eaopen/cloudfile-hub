"""Trusted OIDC native read-ticket issuer; no public route or legacy fallback."""
from copy import deepcopy
import json
import re
from uuid import UUID

from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from ..resources.paths import resource_ref
from .native_session import SESSION_REFERENCE_KEY
from .session_authority import OIDCSessionAuthority


class OIDCReadTicketIssuer:
    def __init__(self, preparation, authority):
        if (not isinstance(preparation, SubjectPreparation)
                or not isinstance(authority, OIDCSessionAuthority)):
            raise ValueError("actual subject preparation and session authority required")
        self.preparation, self.authority = preparation, authority

    def issue(self, request, reference, *, head_id, object_id, operation="download"):
        ref = resource_ref(reference)
        if (ref["kind"] != "file" or operation not in ("view", "download")
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
                    for value in (head_id, object_id))):
            raise ContractError("INVALID_REQUEST", "Exact native file target is required", 400)
        actor = self.preparation.actor
        self.preparation.prepare(actor)  # Directory I/O never under session locks.
        username = self.preparation.state.username(actor)
        # Guard verifies the real signed session and exact current SQL reference.
        # Release before RPC: native RPC acquires these same provider locks.
        with self.authority.guard(request):
            if not request.user.is_authenticated or request.user.username != username:
                raise ContractError("AUTHENTICATION_REQUIRED", "Native identity does not match", 401)
            session_key = request.session.session_key
            session_reference = deepcopy(request.session.get(SESSION_REFERENCE_KEY))
        current = self.preparation.contexts.current(actor)
        if current is None:
            raise ContractError("SUBJECT_UNAVAILABLE", "Current subject is unavailable", 503)
        provider = self.preparation.state.provider
        oidc_provider = "cf_oidc_" + session_reference["scope_hash"][:24]
        conditions = dict(path=ref["path"],
            context=dict(provider=provider, userId=actor, epoch=current["context_epoch"]),
            scopes=[dict(type="provider", provider=provider, external_id=provider),
                dict(type="provider", provider=oidc_provider, external_id=oidc_provider),
                dict(type="user", provider=provider, external_id=actor),
                dict(type="repo", provider="cloudfile", external_id=ref["repo_id"])],
            oidc_session=dict(session_reference, session_key=session_key))
        encoded = json.dumps(conditions, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 16384:
            raise ContractError("INVALID_REQUEST", "Native ticket conditions exceed budget", 400)
        try:
            from seaserv import seafserv_threaded_rpc
            token = seafserv_threaded_rpc.seafile_cloudfile_issue_read_ticket(
                ref["repo_id"], ref["path"], head_id, object_id, operation, username, encoded)
            if not isinstance(token, str) or str(UUID(token)) != token:
                raise ValueError("invalid ticket response")
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Native read ticket is unavailable", 503) from None
        # No grant is cached here: issuance and later consumption/chunks repeat
        # actual native CE/C policy, context, target, session and fence checks.
        return dict(ticket=token, expires_in=60)
