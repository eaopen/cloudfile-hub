"""Short-lived purpose-bound machine credentials using CE's PyJWT dependency."""

from dataclasses import dataclass
from types import MappingProxyType
import time
import re

import jwt

from ..common.errors import ContractError
from ..common.validation import identifier


@dataclass(frozen=True)
class ServiceCredential:
    service_id: str
    issuer: str
    audience: str
    secret: bytes
    scopes: frozenset
    maximum_ttl: int = 300

    def __post_init__(self):
        for value in (self.service_id, self.issuer, self.audience):
            identifier(value)
        if (not isinstance(self.secret, bytes) or len(self.secret) < 32 or
                not isinstance(self.scopes, frozenset) or not self.scopes or
                any(not isinstance(scope, str) or not re.fullmatch(r"[a-z][a-z0-9._:-]{0,127}", scope)
                    for scope in self.scopes) or
                type(self.maximum_ttl) is not int or not 1 <= self.maximum_ttl <= 300):
            raise ValueError("invalid machine credential configuration")


@dataclass(frozen=True)
class ServicePrincipal:
    service_id: str
    scopes: frozenset
    token_id: str
    expires_at: int

    def require(self, scope):
        if scope not in self.scopes:
            raise ContractError("PERMISSION_DENIED", "Service scope is not allowed", 403)


class ServiceTokenVerifier:
    def __init__(self, credentials, *, clock=time.time, clock_skew=30, revocations=None):
        from .service_revocations import ServiceRevocations
        if revocations is not None and not isinstance(revocations, ServiceRevocations):
            raise ValueError("actual service revocation store required")
        self.revocations = revocations
        if (not isinstance(credentials, dict) or not credentials or
                any(not isinstance(value, ServiceCredential) for value in credentials.values()) or
                type(clock_skew) is not int or not 0 <= clock_skew <= 30):
            raise ValueError("invalid service verifier configuration")
        for kid in credentials:
            identifier(kid, maximum=64)
        self.credentials = MappingProxyType(dict(credentials))
        self.clock = clock
        self.clock_skew = clock_skew

    def verify(self, header):
        try:
            if not isinstance(header, str) or not header.startswith("Bearer "):
                raise ValueError()
            token = header[7:]
            if not token or len(token) > 8192 or any(char.isspace() for char in token):
                raise ValueError()
            untrusted = jwt.get_unverified_header(token)
            # A header only selects a configured key, never the algorithm or identity.
            credential = self.credentials.get(untrusted.get("kid"))
            if (credential is None or untrusted.get("alg") != "HS256" or untrusted.get("typ") != "JWT"
                    or set(untrusted) - {"alg", "typ", "kid"}):
                raise ValueError()
            claims = jwt.decode(token, credential.secret, algorithms=["HS256"],
                                issuer=credential.issuer, audience=credential.audience,
                                options={"require": ["iss", "aud", "sub", "iat", "exp", "jti", "scope"],
                                         "verify_iat": False, "verify_exp": False, "verify_nbf": False})
            now = self.clock()
            issued, expires = claims["iat"], claims["exp"]
            if (type(issued) is not int or type(expires) is not int or
                    not 0 < expires - issued <= credential.maximum_ttl or
                    issued > now + self.clock_skew or expires <= now or
                    claims["sub"] != credential.service_id or claims["aud"] != credential.audience or
                    ("nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] > now + self.clock_skew))):
                raise ValueError()
            identifier(claims["jti"], maximum=128)
            if not isinstance(claims["scope"], str):
                raise ValueError()
            scopes = claims["scope"].split(" ")
            if not scopes or any(not value for value in scopes) or len(scopes) != len(set(scopes)):
                raise ValueError()
            scopes = frozenset(scopes)
            if not scopes <= credential.scopes:
                raise ValueError()
            principal = ServicePrincipal(credential.service_id, scopes, claims["jti"], expires)
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, ContractError):
            # Never return the underlying exception, JWT or signing material.
            raise ContractError("AUTHENTICATION_REQUIRED", "Invalid service credential", 401) from None
        self.assert_active(principal)
        return principal

    def assert_active(self, principal):
        if not isinstance(principal, ServicePrincipal) or principal.expires_at <= self.clock():
            raise ContractError("AUTHENTICATION_REQUIRED", "Service credential expired", 401)
        if self.revocations is not None:
            self.revocations.assert_active(principal)
