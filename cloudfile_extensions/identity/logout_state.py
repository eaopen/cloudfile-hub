"""Single-use browser-bound RP return state; no user/session/token snapshot."""
import hashlib
import json
import re
import secrets
from redis.exceptions import RedisError

from ..common.errors import ContractError


LOGOUT_COOKIE = "__Host-cloudfile-logout-binding"


class LogoutStates:
    def __init__(self, redis, *, issuer, client_id, prefix="cf:oidc:logout:"):
        scope = hashlib.sha256(json.dumps([issuer, client_id], separators=(",", ":")).encode()).hexdigest()
        self.redis, self.prefix = redis, prefix + scope + ":"

    def key(self, state):
        if not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", state):
            raise ContractError("AUTHENTICATION_REQUIRED", "Invalid logout state", 401)
        return self.prefix + hashlib.sha256(state.encode()).hexdigest()

    def issue(self):
        state, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        try:
            if not self.redis.set(self.key(state), hashlib.sha256(binding.encode()).hexdigest(), ex=300, nx=True):
                raise ContractError("IDP_STATE_UNAVAILABLE", "Logout state is unavailable", 503)
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Logout state is unavailable", 503) from None
        return state, binding

    def consume(self, state, binding):
        if not isinstance(binding, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", binding):
            raise ContractError("AUTHENTICATION_REQUIRED", "Invalid logout browser binding", 401)
        try:
            accepted = self.redis.eval("""
                if redis.call('PTTL',KEYS[1])<=0 or redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end
                redis.call('DEL',KEYS[1]); return 1
            """, 1, self.key(state), hashlib.sha256(binding.encode()).hexdigest())
            if accepted != 1:
                raise ContractError("AUTHENTICATION_REQUIRED", "Logout state expired or consumed", 401)
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Logout state is unavailable", 503) from None
