"""Trusted login-service delegation issuance, never a file transfer grant."""
import math
import re
from uuid import uuid4
from contextlib import contextmanager
from types import MappingProxyType

import jwt

from ..authorization.read import ContentReadAuthority
from ..authorization.core import PolicyCore
from ..authorization.resources import PolicyResources
from ..common.errors import ContractError
from ..common.validation import identifier
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


class UserDelegationIssueFactory:
    """An explicit login-service grant can nominate its authenticated user.

    This trust is separate from refresh administration; never grant it to a
    browser or generic management client. HTTP adapters must accept no epoch,
    provider, signing key or native username from the request.
    """
    def __init__(self, *, resources, core, service_verifier, signing_keys, cloud_mode):
        if (not isinstance(resources, PolicyResources) or not isinstance(core, PolicyCore)
                or not isinstance(service_verifier, ServiceTokenVerifier)
                or service_verifier.revocations is None
                or service_verifier.revocations.redis is not resources.redis
                or not isinstance(signing_keys, dict) or not signing_keys
                or type(cloud_mode) is not bool):
            raise ValueError("owned policy resources, actual core and revocable login-service grants required")
        keys = {}
        for service, configured in signing_keys.items():
            identifier(service)
            if not isinstance(configured, tuple) or len(configured) != 2:
                raise ValueError("fixed service signing-key mapping required")
            kid, key = configured
            if (not isinstance(key, DelegationKey) or key.service_id != service
                    or key.provider != resources.provider or not isinstance(kid, str)
                    or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", kid)
                    or any(item.secret == key.secret for item in service_verifier.credentials.values())):
                raise ValueError("dedicated fixed-provider delegation key required")
            keys[service] = configured
        self.resources, self.core, self.verifier = resources, core, service_verifier
        self.keys, self.cloud_mode = MappingProxyType(keys), cloud_mode

    @contextmanager
    def __call__(self, request, request_id, user_id):
        if not request.is_secure() or "Cookie" in request.headers or request.GET:
            raise ContractError("AUTHENTICATION_REQUIRED", "Secure login-service authentication is required", 401)
        principal = self.verifier.verify(request.headers.get("Authorization"))
        principal.require(UserDelegationIssuer.ACTION)
        configured = self.keys.get(principal.service_id)
        if configured is None:
            raise ContractError("ACCESS_DENIED", "Login service delegation is not configured", 403)
        identifier(user_id, maximum=225)
        identifier(request_id)
        kid, key = configured
        with self.resources.preparation(user_id, request_id) as preparation:
            authority = ContentReadAuthority(preparation, self.core,
                request_id=request_id, cloud_mode=self.cloud_mode)
            try:
                yield UserDelegationIssuer(authority=authority, service_verifier=self.verifier,
                    signing_key=key, kid=kid)
            finally:
                authority.epoch = None
                authority.current_subject = None
                authority.effective_access = None
                authority.is_owner = False
