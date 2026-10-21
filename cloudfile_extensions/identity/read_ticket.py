"""Trusted native read-ticket issuance for either browser session backend.

No public route and no legacy fallback. The ticket always carries a native
session proof the Server re-checks at issuance and at every consumption, so the
native OIDC session and the legacy Authentik OAuth browser session share one
business identity and one permission result without a client protocol hint.
"""
from copy import deepcopy
import json
from uuid import UUID

from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from ..resources.paths import resource_ref
from .native_session import SESSION_REFERENCE_KEY
from .session_authority import OIDCSessionAuthority
from .ticket_transport import resolve_and_issue_native_ticket

OIDC_REFERENCE_FIELDS = frozenset(
    ("scope_hash", "subject_hash", "sid_hash", "authenticated_at"))
SESSION_KEY_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


def canonical_session_key(value):
    return (isinstance(value, str) and len(value) == 32
        and all(char in SESSION_KEY_ALPHABET for char in value))


class NativeReadTicketIssuer:
    """Shared issuance; a subclass supplies the actual native session proof."""
    directory_access = False

    def __init__(self, preparation, authority, *, directory_access=False):
        if not isinstance(preparation, SubjectPreparation):
            raise ValueError("actual subject preparation required")
        self.preparation, self.authority = preparation, authority
        self.directory_access = directory_access

    def session_proof(self, request, session_key):
        """Return (condition name, condition value, extra provider scopes)."""
        raise NotImplementedError

    def issue(self, request, reference, *, operation="download"):
        ref = resource_ref(reference)
        if ref["kind"] != "file" or operation not in ("view", "download"):
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
            if not canonical_session_key(session_key):
                raise ContractError("AUTHENTICATION_REQUIRED",
                    "Persisted browser session is required", 401)
            name, value, proof_scopes = self.session_proof(request, session_key)
        current = self.preparation.contexts.current(actor)
        if current is None:
            raise ContractError("SUBJECT_UNAVAILABLE", "Current subject is unavailable", 503)
        provider = self.preparation.state.provider
        conditions = dict(path=ref["path"],
            context=dict(provider=provider, userId=actor, epoch=current["context_epoch"]),
            scopes=[dict(type="provider", provider=provider, external_id=provider),
                *proof_scopes,
                dict(type="user", provider=provider, external_id=actor),
                dict(type="repo", provider="cloudfile", external_id=ref["repo_id"])],
            **{name: value})
        if self.directory_access:
            conditions["directory_access"] = True
        encoded = json.dumps(conditions, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 16384:
            raise ContractError("INVALID_REQUEST", "Native ticket conditions exceed budget", 400)
        try:
            token = resolve_and_issue_native_ticket(
                ref["repo_id"], ref["path"], operation, username, encoded)
            if not isinstance(token, str) or str(UUID(token)) != token:
                raise ValueError("invalid ticket response")
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Native read ticket is unavailable", 503) from None
        # No grant is cached here: issuance and later consumption/chunks repeat
        # actual native CE/C policy, context, target, session and fence checks.
        return dict(ticket=token, expires_in=60)


class OIDCReadTicketIssuer(NativeReadTicketIssuer):
    """Native OIDC session: the Server re-checks the indexed scope and fences."""
    def __init__(self, preparation, authority, *, directory_access=False):
        if not isinstance(authority, OIDCSessionAuthority):
            raise ValueError("actual OIDC session authority required")
        super().__init__(preparation, authority, directory_access=directory_access)

    def session_proof(self, request, session_key):
        reference = deepcopy(request.session.get(SESSION_REFERENCE_KEY))
        scope = reference.get("scope_hash") if isinstance(reference, dict) else None
        if (not isinstance(reference, dict) or set(reference) != OIDC_REFERENCE_FIELDS
                or not isinstance(scope, str) or len(scope) != 64):
            raise ContractError("AUTHENTICATION_REQUIRED",
                "Native OIDC session reference is unavailable", 401)
        oidc_provider = "cf_oidc_" + scope[:24]
        return ("oidc_session", dict(reference, session_key=session_key),
            [dict(type="provider", provider=oidc_provider, external_id=oidc_provider)])


class BrowserReadTicketIssuer(NativeReadTicketIssuer):
    """Legacy CE/Authentik OAuth session; never a synthetic OIDC scope."""
    def __init__(self, preparation, authority, *, directory_access=False):
        # Lazy: browser_session imports read_ticket_http, which imports this module.
        from .browser_session import LegacyBrowserSessionAuthority
        if not isinstance(authority, LegacyBrowserSessionAuthority):
            raise ValueError("actual legacy browser session authority required")
        super().__init__(preparation, authority, directory_access=directory_access)

    def session_proof(self, request, session_key):
        # Logout deletes this exact persisted row, so the Server's live-session
        # lock is the equivalent of the OIDC logout fence. No OIDC fields and no
        # cf_oidc_* provider scope are invented for a non-OIDC login.
        return "browser_session", dict(session_key=session_key), []
