"""Verified backchannel notification only, not replay acceptance or session deletion."""
from dataclasses import dataclass
import time
import jwt

from ..common.errors import ContractError
from ..common.validation import identifier
from .oidc import OIDCConfig, SigningKeys


EVENT = "http://schemas.openid.net/event/backchannel-logout"


@dataclass(frozen=True)
class LogoutNotification:
    issuer: str
    client_id: str
    jti: str
    subject: str
    session_id: str
    issued_at: int
    expires_at: int


def rejected():
    return ContractError("AUTHENTICATION_REQUIRED", "Backchannel logout token is invalid", 401)


class LogoutTokenValidator:
    def __init__(self, config, keys, *, clock=time.time):
        if (not isinstance(config, OIDCConfig) or not isinstance(keys, SigningKeys)
                or keys.url != config.jwks_url or not callable(clock)):
            raise ValueError("actual fixed OIDC configuration and signing keys required")
        self.config, self.keys, self.clock = config, keys, clock

    def validate(self, token):
        try:
            if not isinstance(token, str) or not 1 <= len(token) <= 32768 or any(char.isspace() for char in token):
                raise ValueError()
            header = jwt.get_unverified_header(token)
            if (set(header) - {"alg", "typ", "kid"} or header.get("alg") != "RS256"
                    or header.get("typ", "JWT") not in {"JWT", "logout+jwt"}):
                raise ValueError()
            kid = identifier(header.get("kid"), maximum=128)
        except (jwt.PyJWTError, ValueError, TypeError, ContractError):
            raise rejected() from None
        # Preserve actual JWKS service failure rather than accepting old keys
        # or conflating an unavailable provider with a valid notification.
        key = self.keys.get(kid)
        try:
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.config.client_id,
                issuer=self.config.issuer, options={"require": ["iss", "aud", "iat", "exp", "jti", "events"],
                    "verify_iat": False, "verify_exp": False, "verify_nbf": False})
            now = self.clock()
            issued, expires = claims["iat"], claims["exp"]
            if (type(issued) is not int or type(expires) is not int
                    or not now - 300 <= issued <= now + 30
                    or not issued < expires <= issued + 300 or expires <= now
                    or "nonce" in claims or claims["events"] != {EVENT: {}}
                    or ("nbf" in claims and (type(claims["nbf"]) is not int
                        or claims["nbf"] > now + 30 or claims["nbf"] >= expires))):
                raise ValueError()
            subject, session_id = claims.get("sub"), claims.get("sid")
            if subject is None and session_id is None:
                raise ValueError()
            for value in (subject, session_id):
                if value is not None:
                    identifier(value)
            return LogoutNotification(self.config.issuer, self.config.client_id,
                identifier(claims["jti"], maximum=128), subject, session_id, issued, expires)
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, ContractError):
            raise rejected() from None
