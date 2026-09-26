"""CF-only fixed-TTL subject contexts with single-flight and lease/epoch CAS.

Projection and durable barriers are supplied by the trusted native coordinator.
There is no stale fallback after expiry, login or a requested force refresh.
"""

import hashlib
import json
import math
import secrets
import time
from uuid import uuid4

from redis.exceptions import RedisError

from ..common.errors import ContractError
from ..common.validation import identifier
from .protocol import validate_subject


def unavailable():
    return ContractError("SUBJECT_UNAVAILABLE", "Subject authorization is unavailable", 503)


class SubjectContexts:
    def __init__(self, redis, *, provider_id, fetch, attribute_allowlist,
                 account_active, barrier_active, refresh_guard, project,
                 prefix="cf:subjects:", ttl=1800, jitter=None,
                 clock=time.time, wait_seconds=2):
        identifier(provider_id)
        if jitter is None:
            jitter = lambda: secrets.randbelow(ttl // 10 + 1)
        if (type(ttl) is not int or not 60 <= ttl <= 1800 or
                not 0 <= wait_seconds <= 5 or
                not all(callable(value) for value in (fetch, account_active, barrier_active, refresh_guard, project, jitter, clock))):
            raise ValueError("invalid subject context configuration")
        self.redis = redis
        self.provider_id = provider_id
        self.fetch = fetch
        self.allowlist = frozenset(attribute_allowlist)
        self.account_active = account_active
        self.barrier_active = barrier_active
        self.refresh_guard = refresh_guard
        self.project = project
        self.prefix = prefix
        self.ttl = ttl
        self.jitter = jitter
        self.clock = clock
        self.wait_seconds = wait_seconds

    def _keys(self, user_id):
        identifier(user_id, maximum=225)
        digest = hashlib.sha256(json.dumps([self.provider_id, user_id], separators=(",", ":")).encode()).hexdigest()
        return self.prefix + digest, self.prefix + digest + ":lease"

    def _read(self, user_id):
        key, _ = self._keys(user_id)
        raw = self.redis.get(key)
        if not raw:
            return None
        try:
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get("userId") != user_id:
                raise ValueError()
            expiry = value["expires_at"]
            if type(expiry) not in (int, float) or not math.isfinite(expiry):
                raise ValueError()
            epoch = value["context_epoch"]
            if not isinstance(epoch, str) or len(epoch) != 32 or any(c not in "0123456789abcdef" for c in epoch):
                raise ValueError()
            if value["status"] not in {"refreshing", "unavailable", "ready", "disabled"}:
                raise ValueError()
            if value["status"] in {"ready", "disabled"}:
                fetched = value["fetched_at"]
                if (type(fetched) not in (int, float) or not math.isfinite(fetched) or
                        not 0 < expiry - fetched <= self.ttl or fetched > self.clock() + 60):
                    raise ValueError()
                subject = validate_subject(value["subject"], requested_user_id=user_id,
                                           attribute_allowlist=self.allowlist)
                if (value["source_etag"] != subject["etag"] or
                        (value["status"] == "ready") != (subject["status"] == "active")):
                    raise ValueError()
            if value["expires_at"] <= self.clock():
                return None
            return value
        except (ValueError, TypeError, KeyError, ContractError):
            raise unavailable() from None

    def current(self, user_id):
        try:
            if not self.account_active(user_id):
                raise ContractError("SUBJECT_DISABLED", "Subject is disabled", 403)
            if self.barrier_active(self.provider_id, user_id):
                raise unavailable()
            value = self._read(user_id)
            if value and value.get("status") == "disabled":
                raise ContractError("SUBJECT_DISABLED", "Subject is disabled", 403)
            if value and value.get("status") == "ready":
                return value
            return None
        except RedisError:
            # A direct-source degraded mode needs the same native consistency
            # guarantees; until that adapter exists, fail closed, never use stale.
            raise unavailable() from None

    def get(self, user_id, *, trigger="request"):
        if trigger not in {"request", "login", "force"}:
            raise ValueError("invalid context refresh trigger")
        current = self.current(user_id)
        if current is not None and trigger == "request":
            return current
        return self.prepare(user_id, reuse_ready=trigger == "request")

    def prepare(self, user_id, *, reuse_ready=False, _retry_after_join=True):
        key, lease_key = self._keys(user_id)
        epoch = uuid4().hex
        try:
            pending = {"userId": user_id, "status": "refreshing", "context_epoch": epoch,
                       "expires_at": self.clock() + self.ttl}
            # Cache recheck, lease acquisition and generation publication are one
            # Redis operation; a completed concurrent refresh cannot cause a gap.
            # Starting a generation must use the same authority coordinator as
            # projection/publication. Redis lease expiry alone must not let a
            # successor invalidate an in-flight native projection under its guard.
            # Source I/O and join waits remain outside this bounded guard.
            with self.refresh_guard(user_id, epoch):
                started = self.redis.eval('''
                local raw = redis.call('GET', KEYS[1])
                local old = nil
                if raw then old = cjson.decode(raw) end
                if old and old.expires_at <= tonumber(ARGV[4]) then old=nil; raw=nil end
                local owner = redis.call('GET', KEYS[2])
                if owner then return {0, raw or '', owner} end
                if ARGV[5]=='1' and old and old.status=='ready' then return {2, raw, ''} end
                local pending = cjson.decode(ARGV[2])
                redis.call('SET', KEYS[2], ARGV[1], 'EX', 30)
                redis.call('SET', KEYS[1], cjson.encode(pending), 'EX', ARGV[3])
                return {1, raw or '', ''}
                ''', 2, key, lease_key, epoch, json.dumps(pending), self.ttl, self.clock(), int(reuse_ready))
            if started[0] == 2:
                value = self.current(user_id)
                if value is None:
                    raise unavailable()
                return value
            if started[0] == 0:
                # Join the existing refresh without issuing another source fetch.
                joining = started[2]
                if isinstance(joining, bytes):
                    joining = joining.decode()
                deadline = time.monotonic() + self.wait_seconds
                while time.monotonic() < deadline:
                    value = self.current(user_id)
                    if value is not None and value.get("context_epoch") == joining:
                        if reuse_ready:
                            return value
                        # Login/force must not reuse a fetch started before this
                        # trigger: it may precede a directory permission change.
                        # Wait for its owner to finish, then perform a new read.
                        owner = self.redis.get(lease_key)
                        if isinstance(owner, bytes):
                            owner = owner.decode()
                        if owner != joining:
                            if not _retry_after_join:
                                raise unavailable()
                            return self.prepare(user_id, reuse_ready=False, _retry_after_join=False)
                    time.sleep(0.02)
                raise unavailable()
            try:
                subject = validate_subject(self.fetch(user_id), requested_user_id=user_id,
                                           attribute_allowlist=self.allowlist)
                # Ordering belongs to this refresh lease/epoch, not source hashes
                # or optional source metadata. Fetch must use a coherent primary
                # DB snapshot without response caching or asynchronous replicas.
                jitter = self.jitter()
                if type(jitter) is not int or not 0 <= jitter <= self.ttl // 10:
                    raise ValueError("context jitter must only shorten TTL by at most ten percent")
                duration = self.ttl - jitter
                now = self.clock()
                value = {"userId": user_id, "status": "ready" if subject["status"] == "active" else "disabled",
                         "context_epoch": epoch, "source_etag": subject["etag"], "fetched_at": now,
                         "expires_at": now + duration, "subject": subject}
                # This guard must hold the durable scope fence/coordinator. The
                # projection callback must reconcile removals as well as additions.
                with self.refresh_guard(user_id, epoch):
                    self._assert_lease(lease_key, epoch)
                    self.project(subject, epoch)
                    if subject["status"] == "active" and not self.account_active(user_id):
                        raise ContractError("SUBJECT_DISABLED", "Subject is disabled", 403)
                    published = self.redis.eval('''
                        if redis.call('GET', KEYS[2]) ~= ARGV[1] then return 0 end
                        local previous = redis.call('GET', KEYS[1])
                        if not previous or cjson.decode(previous).context_epoch ~= ARGV[1] then return 0 end
                        redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
                        return 1
                    ''', 2, key, lease_key, epoch, json.dumps(value), duration)
                    if published != 1:
                        raise unavailable()
                if value["status"] == "disabled":
                    raise ContractError("SUBJECT_DISABLED", "Subject is disabled", 403)
                return value
            except Exception as error:
                pending["status"] = "unavailable"
                # Failure is also a current-generation state transition. It
                # cannot race a final consumer holding the authority guard.
                with self.refresh_guard(user_id, epoch):
                    self.redis.eval('''
                    if redis.call('GET', KEYS[2]) == ARGV[1] then
                        local value = redis.call('GET', KEYS[1])
                        if value and cjson.decode(value).context_epoch == ARGV[1] and
                           cjson.decode(value).status ~= 'disabled' then
                            redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
                        end
                    end
                    ''', 2, key, lease_key, epoch, json.dumps(pending), self.ttl)
                if isinstance(error, ContractError):
                    raise
                raise unavailable() from None
            finally:
                self.redis.eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
                                1, lease_key, epoch)
        except RedisError:
            raise unavailable() from None

    def _assert_lease(self, key, epoch):
        current = self.redis.get(key)
        if isinstance(current, bytes):
            current = current.decode()
        if current != epoch:
            raise unavailable()

    @staticmethod
    def public_state(value):
        from datetime import datetime, timezone
        return {"userId": value["userId"], "status": value["status"],
                "context_epoch": value["context_epoch"],
                "fetched_at": datetime.fromtimestamp(value["fetched_at"], timezone.utc).isoformat().replace("+00:00", "Z"),
                "expires_at": datetime.fromtimestamp(value["expires_at"], timezone.utc).isoformat().replace("+00:00", "Z")}
