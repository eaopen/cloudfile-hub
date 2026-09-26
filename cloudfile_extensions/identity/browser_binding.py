"""Volatile browser login bindings, independent of authenticated user sessions."""
import hashlib
import re
import secrets

from redis.exceptions import RedisError

from ..common.errors import ContractError


BINDING_COOKIE = "__Host-cloudfile-login-binding"


def request_binding(request):
    """Reject duplicate or ambiguously parsed browser proof cookies."""
    raw = request.headers.get("Cookie", "")
    if len(raw) > 8192:
        raise ContractError("AUTHENTICATION_REQUIRED", "Browser binding cookie is invalid", 401)
    values = [part.strip().split("=", 1)[1] for part in raw.split(";")
        if "=" in part and part.strip().split("=", 1)[0] == BINDING_COOKIE]
    if (len(values) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", values[0])
            or request.COOKIES.get(BINDING_COOKIE) != values[0]):
        raise ContractError("AUTHENTICATION_REQUIRED", "Exact browser login binding required", 401)
    return values[0]


class BrowserLoginBindings:
    def __init__(self, redis, *, prefix="cf:oidc:browser:"):
        self.redis, self.prefix = redis, prefix

    def key(self, binding):
        if not isinstance(binding, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", binding):
            raise ContractError("AUTHENTICATION_REQUIRED", "Browser login binding is invalid", 401)
        return self.prefix + hashlib.sha256(binding.encode()).hexdigest()

    def rotate(self, request, response):
        if not request.is_secure():
            raise ContractError("AUTHENTICATION_REQUIRED", "Secure browser login is required", 401)
        binding = secrets.token_urlsafe(32)
        try:
            # 300 seconds for the OIDC flow plus at most 300 pending status.
            if not self.redis.set(self.key(binding), "1", ex=600, nx=True):
                raise ContractError("IDP_STATE_UNAVAILABLE", "Browser login state is unavailable", 503)
            old = request.COOKIES.get(BINDING_COOKIE)
            if isinstance(old, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", old):
                self.redis.delete(self.key(old))
            response.set_cookie(BINDING_COOKIE, binding, max_age=600, path="/", secure=True,
                                httponly=True, samesite="Lax")
            return binding
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Browser login state is unavailable", 503) from None

    def clear(self, binding, response):
        try:
            self.redis.delete(self.key(binding))
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Browser login state is unavailable", 503) from None
        response.set_cookie(BINDING_COOKIE, "", max_age=0, path="/", secure=True,
                            httponly=True, samesite="Lax")

    def assert_active(self, binding):
        try:
            valid = self.redis.eval("if redis.call('GET',KEYS[1])=='1' and redis.call('PTTL',KEYS[1])>0 then return 1 end return 0",
                                    1, self.key(binding))
            if valid != 1:
                raise ContractError("AUTHENTICATION_REQUIRED", "Browser login binding expired", 401)
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Browser login state is unavailable", 503) from None
