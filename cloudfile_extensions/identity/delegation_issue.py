"""Trusted login-service delegation issuance, never a file transfer grant."""
import math
import re
from uuid import uuid4

import jwt

from ..authorization.read import ContentReadAuthority
from ..common.errors import ContractError
from ..resources.paths import resource_ref
from .service_tokens import ServiceTokenVerifier
from .user_delegation import DelegationKey


class UserDelegationIssuer:
    ACTION = "user.delegation.issue"

    def __init__(self, *, authority, service_verifier, signing_key, kid):
        if (type(authority) is not ContentReadAuthority
                or not isinstance(service_verifier, ServiceTokenVerifier)
                or service_verifier.revocations is None
                or not isinstance(signing_key, DelegationKey)
                or not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", kid)
                or signing_key.provider != authority.state.provider):
            raise ValueError("actual read authority, revocable service authentication and dedicated key required")
        if any(item.secret == signing_key.secret for item in service_verifier.credentials.values()):
            raise ValueError("delegation key must differ from machine credential keys")
        self.authority, self.verifier = authority, service_verifier
        self.key, self.kid = signing_key, kid

    def issue(self, request, reference, *, operation="download"):
        if not request.is_secure() or "Cookie" in request.headers or request.GET:
            raise ContractError("AUTHENTICATION_REQUIRED", "Secure login-service authentication is required", 401)
        principal = self.verifier.verify(request.headers.get("Authorization"))
        principal.require(self.ACTION)
        if principal.service_id != self.key.service_id:
            raise ContractError("ACCESS_DENIED", "Login service is not allowed to issue this delegation", 403)
        ref = resource_ref(reference)
        if ref["kind"] != "file" or operation not in ("view", "download"):
            raise ContractError("INVALID_REQUEST", "Exact delegated file action is required", 400)

        def capture_epoch(cursor, target):
            # Only returns the currently authorized subject version. No token,
            # RPC, native file publication or permission effect in this scope.
            self.verifier.assert_active(principal)
            return self.authority.epoch

        epoch = self.authority.consume(ref, capture_epoch)
        current = self.authority.preparation.contexts.current(self.authority.actor)
        if current is None or current["context_epoch"] != epoch:
            raise ContractError("SUBJECT_UNAVAILABLE", "Delegation subject changed", 503)
        self.verifier.assert_active(principal)
        now = math.floor(self.verifier.clock())
        expires = min(now + 60, principal.expires_at)
        if expires <= now:
            raise ContractError("AUTHENTICATION_REQUIRED", "Login service credential expired", 401)
        token = jwt.encode(dict(iss=self.key.issuer, aud=self.key.audience, sub=principal.service_id,
            iat=now, exp=expires, jti=str(uuid4()), userId=self.authority.actor,
            provider=self.key.provider, context_epoch=epoch, resource=ref, action=operation),
            self.key.secret, algorithm="HS256", headers=dict(kid=self.kid, typ="cf-user-delegation+jwt"))
        # This signed claim cannot bypass subsequent verifier/current epoch,
        # exact resource/action, native CE/C, TTL or revocation checks.
        return dict(delegation=token, expires_in=expires - now)
