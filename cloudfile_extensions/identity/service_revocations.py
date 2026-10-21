"""Trusted short-lived service token revocations; no public management grant."""
import hashlib
import json
import math
import time

from ..common.errors import ContractError
from ..common.validation import identifier


class ServiceRevocations:
    def __init__(self, redis, *, prefix="cf:service-revocations:", clock=time.time):
        if (not isinstance(prefix, str) or not prefix.startswith("cf:") or not prefix.endswith(":")
                or len(prefix) > 128 or not callable(clock)):
            raise ValueError("fixed CloudFile revocation namespace required")
        self.redis, self.prefix, self.clock = redis, prefix, clock

    def _key(self, service_id, token_id):
        identifier(service_id)
        identifier(token_id, maximum=128)
        return self.prefix + hashlib.sha256(json.dumps([service_id, token_id],
            ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()

    def assert_active(self, principal):
        try:
            value = self.redis.get(self._key(principal.service_id, principal.token_id))
            if value not in (None, b"1", "1"):
                raise ValueError()
        except Exception:
            raise ContractError("SERVICE_UNAVAILABLE", "Service revocation state is unavailable", 503) from None
        if value is not None:
            raise ContractError("AUTHENTICATION_REQUIRED", "Service credential was revoked", 401)

    def revoke(self, principal, *, retention=0):
        """Trusted operator receives a verified principal; never raw HTTP IDs."""
        from .service_tokens import ServicePrincipal
        if not isinstance(principal, ServicePrincipal):
            raise ValueError("verified service principal required")
        if type(retention) is not int or not 0 <= retention <= 300:
            raise ValueError("bounded native transfer retention required")
        remaining = principal.expires_at - self.clock()
        if not math.isfinite(remaining) or remaining > 330:
            raise ValueError("invalid revocation lifetime")
        remaining += retention
        if remaining <= 0:
            return False
        ttl = math.ceil(remaining) + 1
        try:
            # Repeated revocation never shortens an existing marker. A corrupt
            # marker is not repaired into a permissive state.
            result = self.redis.eval('''
                local value = redis.call('GET', KEYS[1])
                if value and value ~= '1' then return -1 end
                if not value or redis.call('TTL', KEYS[1]) < tonumber(ARGV[1]) then
                    redis.call('SET', KEYS[1], '1', 'EX', ARGV[1])
                end
                return 1
            ''', 1, self._key(principal.service_id, principal.token_id), ttl)
            if result != 1:
                raise ValueError()
            return True
        except Exception:
            raise ContractError("SERVICE_UNAVAILABLE", "Service revocation state is unavailable", 503) from None
