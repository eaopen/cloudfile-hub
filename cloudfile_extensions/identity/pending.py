"""Browser-bound, non-sliding pending-status proofs; no file/session authority."""
import hashlib
import json
import re
import secrets
import time
from uuid import UUID

from redis.exceptions import RedisError

from ..common.errors import ContractError
from .bindings import IdentityBindings


def rejected():
    return ContractError("AUTHENTICATION_REQUIRED", "Pending login proof is invalid or expired", 401)


class PendingLoginProofs:
    def __init__(self, redis, *, prefix="cf:oidc:pending:", clock=time.time):
        self.redis, self.prefix, self.clock = redis, prefix, clock

    @staticmethod
    def _binding(binding):
        if not isinstance(binding, str) or not 32 <= len(binding) <= 512:
            raise rejected()
        return hashlib.sha256(binding.encode()).hexdigest()

    def _key(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise rejected()
        return self.prefix + hashlib.sha256(token.encode()).hexdigest()

    def issue(self, identity, job_id, binding):
        IdentityBindings._identity(identity["issuer"], identity["sub"], identity["userId"])
        if str(UUID(job_id)) != job_id or type(identity.get("expires_at")) is not int:
            raise rejected()
        ttl = min(300, int(identity["expires_at"] - self.clock()))
        if ttl <= 0:
            raise rejected()
        token = secrets.token_urlsafe(32)
        value = dict(identity={key: identity[key] for key in ("issuer", "sub", "userId", "expires_at")},
                     job_id=job_id, binding=self._binding(binding), expires_at=self.clock() + ttl)
        try:
            if not self.redis.set(self._key(token), json.dumps(value), ex=ttl, nx=True):
                raise rejected()
            return token
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Pending login state is unavailable", 503) from None

    def read(self, token, binding):
        try:
            raw = self.redis.eval('''
                if redis.call('PTTL', KEYS[1]) <= 0 then return false end
                local raw = redis.call('GET', KEYS[1])
                if not raw or string.len(raw)>16384 then return false end
                local ok, value = pcall(cjson.decode, raw)
                if not ok or type(value) ~= 'table' or value.binding ~= ARGV[1] then return false end
                return raw
            ''', 1, self._key(token), self._binding(binding))
            if not raw:
                raise rejected()
            value = json.loads(raw)
            identity = value["identity"]
            IdentityBindings._identity(identity["issuer"], identity["sub"], identity["userId"])
            if (str(UUID(value["job_id"])) != value["job_id"] or type(identity["expires_at"]) is not int or
                    identity["expires_at"] <= self.clock() or type(value["expires_at"]) not in (int, float) or
                    not self.clock() < value["expires_at"] <= identity["expires_at"]):
                raise rejected()
            return identity, value["job_id"]
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Pending login state is unavailable", 503) from None
        except (ValueError, TypeError, KeyError, AttributeError):
            raise rejected() from None

    def revoke(self, token):
        try:
            self.redis.delete(self._key(token))
        except RedisError:
            raise ContractError("IDP_STATE_UNAVAILABLE", "Pending login state is unavailable", 503) from None


class PendingLoginStatus:
    def __init__(self, proofs, provisioning):
        from .provisioning import ProvisioningJobs
        if not isinstance(proofs, PendingLoginProofs) or not isinstance(provisioning, ProvisioningJobs):
            raise ValueError("trusted pending status assembly required")
        self.proofs, self.provisioning = proofs, provisioning

    def status(self, token, binding):
        identity, job_id = self.proofs.read(token, binding)
        return self.provisioning.status_for_login(identity, job_id)
