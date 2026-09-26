"""Independent exact-resource user delegation verifier; no HTTP enablement.

Signing keys are dedicated trusted-login-service configuration, never machine
refresh keys or request-selected identity providers. Verification alone is not
current subject/native content authorization.
"""
from dataclasses import dataclass
from types import MappingProxyType
import re
import time

import jwt

from ..common.errors import ContractError
from ..common.validation import identifier
from ..resources.paths import resource_ref
from .service_tokens import ServicePrincipal
from .service_revocations import ServiceRevocations


@dataclass(frozen=True)
class DelegationKey:
    service_id: str
    issuer: str
    audience: str
    provider: str
    secret: bytes

    def __post_init__(self):
        for value in (self.service_id, self.issuer, self.audience):
            identifier(value)
        identifier(self.provider, maximum=32)
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValueError("dedicated delegation signing key required")


@dataclass(frozen=True)
class UserDelegation:
    service_id: str
    user_id: str
    provider: str
    epoch: str
    resource: object
    action: str
    token_id: str
    expires_at: int

    def require(self, reference, action):
        if dict(self.resource) != resource_ref(reference) or self.action != action:
            raise ContractError("ACCESS_DENIED", "Delegated resource or action is not allowed", 403)


class UserDelegationVerifier:
    def __init__(self, keys, *, revocations, clock=time.time):
        if (not isinstance(keys, dict) or not keys
                or any(not isinstance(key, DelegationKey) for key in keys.values())
                or not isinstance(revocations, ServiceRevocations)):
            raise ValueError("dedicated delegation keys and actual revocation store required")
        for kid in keys:
            identifier(kid, maximum=64)
        self.keys, self.revocations, self.clock = MappingProxyType(dict(keys)), revocations, clock

    def verify(self, header):
        try:
            if not isinstance(header, str) or not header.startswith("Bearer "):
                raise ValueError()
            token = header[7:]
            if not token or len(token) > 16384 or any(char.isspace() for char in token):
                raise ValueError()
            metadata = jwt.get_unverified_header(token)
            key = self.keys.get(metadata.get("kid"))
            if (key is None or metadata.get("alg") != "HS256"
                    or metadata.get("typ") != "cf-user-delegation+jwt"
                    or set(metadata) != {"alg", "typ", "kid"}):
                raise ValueError()
            fields = {"iss", "aud", "sub", "iat", "exp", "jti", "userId", "provider",
                "context_epoch", "resource", "action"}
            claims = jwt.decode(token, key.secret, algorithms=["HS256"], issuer=key.issuer,
                audience=key.audience, options={"require": list(fields),
                    "verify_iat": False, "verify_exp": False, "verify_nbf": False})
            issued, expires, now = claims["iat"], claims["exp"], self.clock()
            if (set(claims) != fields or claims["sub"] != key.service_id
                    or claims["aud"] != key.audience or claims["provider"] != key.provider
                    or type(issued) is not int or type(expires) is not int
                    or not 0 < expires - issued <= 60 or issued > now + 30 or expires <= now
                    or not isinstance(claims["context_epoch"], str)
                    or not re.fullmatch(r"[0-9a-f]{32}", claims["context_epoch"])
                    or claims["action"] not in ("view", "download")):
                raise ValueError()
            identifier(claims["userId"], maximum=225)
            identifier(claims["jti"], maximum=128)
            resource = resource_ref(claims["resource"])
            if resource["kind"] != "file":
                raise ValueError()
            principal = UserDelegation(key.service_id, claims["userId"], key.provider,
                claims["context_epoch"], MappingProxyType(resource), claims["action"],
                claims["jti"], expires)
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, ContractError):
            raise ContractError("AUTHENTICATION_REQUIRED", "Invalid user delegation", 401) from None
        self.assert_active(principal)
        return principal

    def assert_active(self, principal):
        if not isinstance(principal, UserDelegation) or principal.expires_at <= self.clock():
            raise ContractError("AUTHENTICATION_REQUIRED", "User delegation expired", 401)
        self.revocations.assert_active(ServicePrincipal(principal.service_id,
            frozenset({"user.delegation"}), principal.token_id, principal.expires_at))

    def revoke(self, principal):
        """Trusted operator only; no raw request subject/token ID accepted."""
        if not isinstance(principal, UserDelegation):
            raise ValueError("verified user delegation required")
        return self.revocations.revoke(ServicePrincipal(principal.service_id,
            frozenset({"user.delegation"}), principal.token_id, principal.expires_at))
