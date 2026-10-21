"""Opaque, short-lived pagination state; never an authorization credential."""
import hashlib
import hmac
import json
import re
import secrets
import time

from ..common.errors import ContractError
from .meilisearch import _object, unavailable


class SearchCursorStore:
    REQUIRED = {"user_id", "context_epoch", "policy_revision", "index_generation", "query"}

    def __init__(self, redis, *, secret, clock=time.time):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("search cursor signing secret required")
        self.redis, self.secret, self.clock = redis, secret, clock

    def _scope(self, scope):
        try:
            if not isinstance(scope, dict) or set(scope) != self.REQUIRED:
                raise ValueError()
            for name in self.REQUIRED - {"query"}:
                if not isinstance(scope[name], str) or not scope[name] or len(scope[name]) > 512:
                    raise ValueError()
            if not isinstance(scope["query"], dict):
                raise ValueError()
            raw = json.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            if len(raw) > 16384:
                raise ValueError()
            return hmac.new(self.secret, b"cf.search.cursor.v1\n" + raw, hashlib.sha256).hexdigest()
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("trusted complete search scope required") from None

    def issue(self, *, scope, offset, expires_at=None):
        digest = self._scope(scope)
        if type(offset) is not int or not 0 <= offset <= 10000:
            raise ValueError("bounded candidate offset required")
        now = int(self.clock())
        expiry = now + 300 if expires_at is None else expires_at
        if type(expiry) is not int or not now < expiry <= now + 300:
            raise ValueError("bounded cursor lifetime required")
        token = secrets.token_hex(32)
        raw = json.dumps(dict(version=1, scope=digest, offset=offset, expires=expiry), separators=(",", ":"))
        try:
            if self.redis.set("cf:search:cursor:" + token, raw, ex=expiry - now, nx=True) is not True:
                raise ValueError()
        except Exception:
            raise unavailable() from None
        return token

    def resolve(self, token, *, scope):
        digest = self._scope(scope)
        invalid = ContractError("INVALID_CURSOR", "Search cursor expired or changed", 400)
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise invalid
        try:
            raw = self.redis.get("cf:search:cursor:" + token)
        except Exception:
            raise unavailable() from None
        try:
            if not isinstance(raw, (str, bytes)) or len(raw) > 512:
                raise ValueError()
            value = json.loads(raw, object_pairs_hook=_object)
            now = int(self.clock())
            if (not isinstance(value, dict) or set(value) != {"version", "scope", "offset", "expires"} or
                    type(value["version"]) is not int or value["version"] != 1 or
                    not isinstance(value["scope"], str) or not hmac.compare_digest(value["scope"], digest) or
                    type(value["offset"]) is not int or not 0 <= value["offset"] <= 10000 or
                    type(value["expires"]) is not int or not now < value["expires"] <= now + 300):
                raise ValueError()
            return value["offset"], value["expires"]
        except (ValueError, TypeError, UnicodeError):
            raise invalid from None
