"""Actual isolated Redis tests. Native projection/guard remain explicit fixtures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from threading import Event, Lock
import unittest
from unittest.mock import patch
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.contexts import SubjectContexts
from cloudfile_extensions.identity.oidc import RedisLoginFlows


@unittest.skipUnless(os.environ.get("CF_TEST_REDIS_PORT"), "requires isolated CloudFile test Redis")
class ContextTest(unittest.TestCase):
    def setUp(self):
        import redis
        self.redis = redis.Redis(host=os.environ.get("CF_TEST_REDIS_HOST", "127.0.0.1"), port=int(os.environ["CF_TEST_REDIS_PORT"]))
        self.prefix = "cf:test:" + uuid4().hex + ":"
        self.source_calls = 0
        self.projections = []
        self.active = True
        self.barrier = False
        self.source = {"userId": "u1", "status": "active", "attributes": {"employee_no": "E001"},
                       "organizations": [{"namespace": "dept", "external_id": "d1", "is_primary": True}],
                       "roles": [{"namespace": "role", "external_id": "r1"}], "revision": "1",
                       "organization_revision": "1", "etag": "etag-1",
                       "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        @contextmanager
        def guard(user_id, epoch, *, phase):
            yield
        self.contexts = SubjectContexts(self.redis, provider_id="directory", fetch=self.fetch,
                                        attribute_allowlist={"employee_no"}, account_active=lambda u: self.active,
                                        barrier_active=lambda p, u: self.barrier, refresh_guard=guard,
                                        project=lambda source, epoch: self.projections.append(source),
                                        prefix=self.prefix, jitter=lambda: 0)

    def tearDown(self):
        # Only keys in the random namespace created by this test may be removed.
        keys = list(self.redis.scan_iter(match=self.prefix + "*"))
        if keys:
            self.redis.delete(*keys)
        self.redis.close()

    def fetch(self, user_id):
        self.source_calls += 1
        return self.source

    def test_native_utf8_context_key_contract(self):
        import hashlib
        import json
        user = "员工:a:b"
        encoded = json.dumps(["directory", user], ensure_ascii=False, separators=(",", ":")).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        self.assertEqual(self.contexts._keys(user),
                         (self.prefix + digest, self.prefix + digest + ":lease"))

    def test_management_disabled_completion_does_not_grant_read(self):
        self.source = {**self.source, "status": "disabled"}
        value = self.contexts.prepare("u1", allow_disabled=True)
        self.assertEqual(value["status"], "disabled")
        self.assertEqual(self.contexts.completed_state("u1")["context_epoch"], value["context_epoch"])
        with self.assertRaises(ContractError) as caught:
            self.contexts.current("u1")
        self.assertEqual(caught.exception.code, "SUBJECT_DISABLED")
        self.barrier = True
        with self.assertRaises(ContractError):
            self.contexts.completed_state("u1")

    def test_management_force_after_disabled_fetches_new_source(self):
        self.source = {**self.source, "status": "disabled"}
        disabled = self.contexts.prepare("u1", allow_disabled=True)
        self.source = {**self.source, "status": "active", "revision": "2", "etag": "new"}
        ready = self.contexts.prepare("u1", allow_disabled=True)
        self.assertEqual(ready["status"], "ready")
        self.assertNotEqual(ready["context_epoch"], disabled["context_epoch"])
        self.assertEqual(self.source_calls, 2)

    def test_fixed_ttl_hit_login_expiry_and_latest_memberships(self):
        one = self.contexts.get("u1")
        key, _ = self.contexts._keys("u1")
        self.redis.expire(key, 1500)
        self.assertEqual(self.contexts.get("u1"), one)
        self.assertLessEqual(self.redis.ttl(key), 1500)
        self.assertEqual(self.source_calls, 1)
        self.source = {**self.source, "revision": "2", "etag": "etag-2", "roles": []}
        two = self.contexts.get("u1", trigger="login")
        self.assertEqual(two["subject"]["roles"], [])
        self.assertNotEqual(two["context_epoch"], one["context_epoch"])
        self.redis.delete(key)
        three = self.contexts.get("u1")
        self.assertNotEqual(three["context_epoch"], two["context_epoch"])
        self.assertEqual(self.source_calls, 3)

    def test_atomic_projection_generation_assertion(self):
        import json
        epoch = uuid4().hex
        key, lease = self.contexts._keys("u1")
        pending = {"userId": "u1", "status": "refreshing", "context_epoch": epoch,
                   "expires_at": self.contexts.clock() + 1800}
        self.redis.set(key, json.dumps(pending), ex=1800)
        self.redis.set(lease, epoch, ex=30)
        self.contexts.assert_generation("u1", epoch)
        for changed in ({**pending, "status": "ready"},
                        {**pending, "userId": "u2"},
                        {**pending, "context_epoch": uuid4().hex},
                        {**pending, "expires_at": 0},
                        {**pending, "expires_at": self.contexts.clock() + 1900}):
            self.redis.set(key, json.dumps(changed), ex=1800)
            with self.assertRaises(ContractError):
                self.contexts.assert_generation("u1", epoch)
        for raw in ("private-invalid-json", "[]", "null"):
            self.redis.set(key, raw, ex=1800)
            with self.assertRaises(ContractError):
                self.contexts.assert_generation("u1", epoch)
        self.redis.set(key, json.dumps(pending), ex=1800)
        self.redis.persist(lease)
        with self.assertRaises(ContractError):
            self.contexts.assert_generation("u1", epoch)
        self.redis.set(lease, uuid4().hex, ex=30)
        with self.assertRaises(ContractError):
            self.contexts.assert_generation("u1", epoch)
        self.redis.delete(lease)
        with self.assertRaises(ContractError):
            self.contexts.assert_generation("u1", epoch)

    def test_browser_bound_pending_proof_is_fixed_ttl_and_revocable(self):
        import time
        from cloudfile_extensions.identity.pending import PendingLoginProofs
        proofs = PendingLoginProofs(self.redis, prefix=self.prefix)
        identity = dict(issuer="https://idp.example.invalid/", sub="stable", userId="u1",
                        expires_at=int(time.time()) + 600, userinfo={"private": "must-not-save"})
        job = str(uuid4())
        token = proofs.issue(identity, job, "browser-a" * 4)
        key = proofs._key(token)
        self.redis.expire(key, 100)
        stored, actual = proofs.read(token, "browser-a" * 4)
        self.assertEqual(actual, job)
        self.assertNotIn("userinfo", stored)
        self.assertLessEqual(self.redis.ttl(key), 100)
        with self.assertRaises(ContractError):
            proofs.read(token, "browser-b" * 4)
        self.assertEqual(proofs.read(token, "browser-a" * 4)[1], job)
        self.redis.persist(key)
        with self.assertRaises(ContractError):
            proofs.read(token, "browser-a" * 4)

        # External TTL extension cannot extend the stored issuance deadline.
        clock_value = [1000]
        fixed = PendingLoginProofs(self.redis, prefix=self.prefix + "fixed:", clock=lambda: clock_value[0])
        fixed_token = fixed.issue({**identity, "expires_at": 1600}, job, "browser-a" * 4)
        self.redis.expire(fixed._key(fixed_token), 600)
        clock_value[0] = 1301
        with self.assertRaises(ContractError):
            fixed.read(fixed_token, "browser-a" * 4)
        proofs.revoke(token)
        with self.assertRaises(ContractError):
            proofs.read(token, "browser-a" * 4)

    def test_browser_registry_rotation_and_clear_invalidate_all_proofs(self):
        import time
        from unittest.mock import Mock
        from cloudfile_extensions.identity.browser_binding import BrowserLoginBindings, BINDING_COOKIE
        from cloudfile_extensions.identity.pending import PendingLoginProofs
        browser = BrowserLoginBindings(self.redis, prefix=self.prefix + "browser:")
        proofs = PendingLoginProofs(self.redis, prefix=self.prefix + "proof:", browser_bindings=browser)
        request, response = Mock(), Mock()
        request.is_secure.return_value = True
        request.COOKIES = {}
        binding = browser.rotate(request, response)
        browser.assert_active(binding)
        identity = dict(issuer="https://idp.example.invalid/", sub="stable", userId="u1", expires_at=int(time.time()) + 600)
        tokens = [proofs.issue(identity, str(uuid4()), binding) for _ in range(2)]
        for token in tokens:
            proofs.read(token, binding)
        request.COOKIES[BINDING_COOKIE] = binding
        replacement = browser.rotate(request, response)
        with self.assertRaises(ContractError):
            browser.assert_active(binding)
        for token in tokens:
            with self.assertRaises(ContractError):
                proofs.read(token, binding)
        token = proofs.issue(identity, str(uuid4()), replacement)
        browser.clear(replacement, response)
        with self.assertRaises(ContractError):
            browser.assert_active(replacement)
        with self.assertRaises(ContractError):
            proofs.read(token, replacement)
        with self.assertRaises(ContractError):
            proofs.issue(identity, str(uuid4()), replacement)

    def test_fresh_source_outage_is_usable_but_expiry_and_login_fail_closed(self):
        self.contexts.get("u1")
        def down(user_id):
            raise ContractError("SOURCE_UNAVAILABLE", "Source unavailable", 503)
        self.contexts.fetch = down
        self.assertEqual(self.contexts.get("u1")["status"], "ready")
        with self.assertRaises(ContractError):
            self.contexts.get("u1", trigger="login")
        self.assertIsNone(self.contexts.current("u1"))
        key, _ = self.contexts._keys("u1")
        self.redis.delete(key)
        with self.assertRaises(ContractError):
            self.contexts.get("u1")

    def test_current_account_and_durable_barrier_override_cached_ready(self):
        self.contexts.get("u1")
        self.barrier = True
        with self.assertRaises(ContractError):
            self.contexts.get("u1")
        self.barrier = False
        self.active = False
        with self.assertRaises(ContractError) as caught:
            self.contexts.get("u1")
        self.assertEqual(caught.exception.status, 403)

    def test_corrupt_cached_ready_never_authorizes_or_exposes_payload(self):
        import json
        original = self.contexts.get("u1")
        key, _ = self.contexts._keys("u1")
        variants = [
            {**original, "expires_at": float("inf")},
            {**original, "fetched_at": True},
            {**original, "context_epoch": "private-invalid-epoch"},
            {**original, "status": "unknown"},
            {**original, "source_etag": "mismatch"},
            {**original, "subject": {**original["subject"], "userId": "another"}},
            {**original, "subject": {**original["subject"], "status": "disabled"}},
            {**original, "expires_at": original["fetched_at"] + 1801},
        ]
        missing = dict(original)
        missing.pop("subject")
        variants.append(missing)
        for value in variants:
            self.redis.set(key, json.dumps(value), ex=1800)
            with self.assertRaises(ContractError) as caught:
                self.contexts.current("u1")
            self.assertEqual(caught.exception.status, 503)
            self.assertNotIn("private", caught.exception.message)
        self.assertEqual(self.source_calls, 1)

    def test_refresh_without_source_counters_accepts_changed_memberships(self):
        self.contexts.get("u1")
        self.source.pop("revision")
        self.source.pop("organization_revision")
        self.source.update(etag="changed-without-version", roles=[])
        refreshed = self.contexts.prepare("u1")
        self.assertEqual(refreshed["subject"]["roles"], [])
        self.assertNotIn("source_revision", self.contexts.public_state(refreshed))
        self.assertEqual(len(self.projections), 2)

    def test_disabled_snapshot_is_preserved_as_disabled_not_source_failure(self):
        self.source = {**self.source, "status": "disabled", "roles": [], "organizations": []}
        with self.assertRaises(ContractError) as caught:
            self.contexts.prepare("u1")
        self.assertEqual(caught.exception.status, 403)
        key, _ = self.contexts._keys("u1")
        import json
        self.assertEqual(json.loads(self.redis.get(key))["status"], "disabled")

    def test_concurrent_requests_join_one_source_fetch_and_share_epoch(self):
        started, finish = Event(), Event()
        def slow(user_id):
            started.set()
            finish.wait(timeout=5)
            return self.fetch(user_id)
        self.contexts.fetch = slow
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(self.contexts.get, "u1")
            self.assertTrue(started.wait(timeout=2))
            second = executor.submit(self.contexts.get, "u1")
            finish.set()
            one, two = first.result(), second.result()
        self.assertEqual(one["context_epoch"], two["context_epoch"])
        self.assertEqual(self.source_calls, 1)

    def test_late_refresher_cannot_overwrite_new_redis_generation(self):
        import json
        def steal_lease(user_id):
            key, lease_key = self.contexts._keys(user_id)
            self.redis.set(lease_key, "new-generation", ex=30)
            self.redis.set(key, json.dumps({"userId": "u1", "status": "refreshing", "context_epoch": "new-generation",
                                            "expires_at": self.contexts.clock() + 100}), ex=100)
            return self.source
        self.contexts.fetch = steal_lease
        with self.assertRaises(ContractError):
            self.contexts.prepare("u1")
        self.assertEqual(self.projections, [])
        key, lease_key = self.contexts._keys("u1")
        self.assertEqual(self.redis.get(lease_key), b"new-generation")
        self.assertEqual(json.loads(self.redis.get(key))["context_epoch"], "new-generation")

    def test_generation_start_waits_for_projection_guard_after_lease_expiry(self):
        # This lock is an explicit coordinator fixture, not proof of a deployed
        # SQL/native adapter. Real Redis demonstrates generation mutation order.
        entered, finish, contender = Event(), Event(), Event()
        coordinator = Lock()
        @contextmanager
        def guard(user_id, epoch, *, phase):
            if entered.is_set() and not finish.is_set():
                contender.set()
            with coordinator:
                yield
        self.contexts.refresh_guard = guard
        def project(subject, epoch):
            self.projections.append(epoch)
            if len(self.projections) == 1:
                entered.set()
                self.assertTrue(finish.wait(timeout=5))
        self.contexts.project = project
        key, lease_key = self.contexts._keys("u1")
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(self.contexts.prepare, "u1")
            self.assertTrue(entered.wait(timeout=2))
            import json
            old_epoch = json.loads(self.redis.get(key))["context_epoch"]
            self.redis.delete(lease_key)  # deterministic expired lease
            second = executor.submit(self.contexts.prepare, "u1")
            try:
                self.assertTrue(contender.wait(timeout=2))
                self.assertEqual(json.loads(self.redis.get(key))["context_epoch"], old_epoch)
                self.assertFalse(second.done())
            finally:
                finish.set()
            with self.assertRaises(ContractError):
                first.result(timeout=5)
            latest = second.result(timeout=5)
        self.assertNotEqual(latest["context_epoch"], old_epoch)
        self.assertEqual(self.contexts.current("u1"), latest)
        self.assertEqual(len(self.projections), 2)

    def test_start_guard_failure_preserves_generation_without_source_or_projection(self):
        original = self.contexts.get("u1")
        @contextmanager
        def refused(user_id, epoch, *, phase):
            raise ContractError("SUBJECT_UNAVAILABLE", "Subject authorization is unavailable", 503)
            yield
        self.contexts.refresh_guard = refused
        with self.assertRaises(ContractError):
            self.contexts.prepare("u1")
        self.assertEqual(self.contexts.current("u1"), original)
        self.assertEqual(self.source_calls, 1)
        self.assertEqual(len(self.projections), 1)
        _, lease_key = self.contexts._keys("u1")
        self.assertIsNone(self.redis.get(lease_key))

        @contextmanager
        def broken(user_id, epoch, *, phase):
            raise RuntimeError("private coordinator credentials")
            yield
        self.contexts.refresh_guard = broken
        with self.assertRaises(ContractError) as caught:
            self.contexts.prepare("u1")
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("private", caught.exception.message)
        self.assertEqual(self.contexts.current("u1"), original)

    def test_force_does_not_reuse_snapshot_started_before_permission_change(self):
        started, finish, joined = Event(), Event(), Event()
        def fetch(user_id):
            self.source_calls += 1
            snapshot = dict(self.source)
            if self.source_calls == 1:
                started.set()
                self.assertTrue(finish.wait(timeout=5))
            return snapshot
        self.contexts.fetch = fetch
        original_eval = self.redis.eval
        def observed_eval(*args, **kwargs):
            result = original_eval(*args, **kwargs)
            if "ARGV[5]=='1'" in args[0] and args[-1] == 0 and result[0] == 0:
                joined.set()
            return result
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(self.contexts.get, "u1")
            self.assertTrue(started.wait(timeout=2))
            self.source = {**self.source, "roles": [], "etag": "removed-role"}
            with patch.object(self.redis, "eval", side_effect=observed_eval):
                forced = executor.submit(self.contexts.get, "u1", trigger="force")
                try:
                    self.assertTrue(joined.wait(timeout=2))
                finally:
                    finish.set()
                old, latest = first.result(), forced.result()
        self.assertEqual(len(old["subject"]["roles"]), 1)
        self.assertEqual(latest["subject"]["roles"], [])
        self.assertNotEqual(old["context_epoch"], latest["context_epoch"])
        self.assertEqual(self.source_calls, 2)

    def test_oidc_state_is_single_use_browser_bound_and_expires(self):
        flows = RedisLoginFlows(self.redis, prefix=self.prefix)
        state = "s" * 43
        flows.save(state, {"nonce": "n"}, "browser-1")
        with self.assertRaises(ContractError):
            flows.consume(state, "browser-2")
        self.assertEqual(flows.consume(state, "browser-1"), {"nonce": "n"})
        with self.assertRaises(ContractError):
            flows.consume(state, "browser-1")
        flows.save(state, {"nonce": "n"}, "browser-1")
        keys = list(self.redis.scan_iter(match=self.prefix + "*"))
        self.redis.delete(*keys)
        with self.assertRaises(ContractError):
            flows.consume(state, "browser-1")

    def test_projection_failure_does_not_publish_ready_or_leak_underlying_error(self):
        def bad_projection(subject, epoch):
            raise RuntimeError("private connection detail")
        self.contexts.project = bad_projection
        with self.assertRaises(ContractError) as caught:
            self.contexts.prepare("u1")
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("private", caught.exception.message)
        self.assertIsNone(self.contexts.current("u1"))

    def test_projection_time_does_not_extend_source_freshness(self):
        now = [self.contexts.clock()]
        self.contexts.clock = lambda: now[0]
        self.contexts.ttl = 60
        def slow_projection(subject, epoch):
            now[0] += 20
        self.contexts.project = slow_projection
        result = self.contexts.prepare("u1")
        key, _ = self.contexts._keys("u1")
        self.assertEqual(result["expires_at"] - result["fetched_at"], 60)
        self.assertLessEqual(self.redis.ttl(key), 40)
        self.assertEqual(self.contexts.current("u1"), result)

        def expired_projection(subject, epoch):
            now[0] += 60
        self.contexts.project = expired_projection
        with self.assertRaises(ContractError) as caught:
            self.contexts.prepare("u1")
        self.assertEqual(caught.exception.status, 503)
        self.assertIsNone(self.contexts.current("u1"))
        import json
        self.assertEqual(json.loads(self.redis.get(key))["status"], "unavailable")

    def test_guard_phases_distinguish_new_generation_from_owned_publication(self):
        calls = []
        key, lease_key = self.contexts._keys("u1")
        @contextmanager
        def phased(user_id, epoch, *, phase):
            calls.append((epoch, phase))
            if phase == "begin":
                self.assertNotEqual(self.redis.get(lease_key), epoch.encode())
            elif phase == "publish":
                self.assertEqual(self.redis.get(lease_key), epoch.encode())
            elif phase != "fail":
                self.fail("unknown authority phase")
            yield
        self.contexts.refresh_guard = phased
        self.contexts.prepare("u1")
        self.assertEqual([phase for _, phase in calls], ["begin", "publish"])
        self.assertEqual(calls[0][0], calls[1][0])
        calls.clear()
        def failed(subject, epoch):
            raise RuntimeError("private projection failure")
        self.contexts.project = failed
        with self.assertRaises(ContractError):
            self.contexts.prepare("u1")
        self.assertEqual([phase for _, phase in calls], ["begin", "publish", "fail"])
        self.assertEqual(len({epoch for epoch, _ in calls}), 1)
        self.assertIsNone(self.contexts.current("u1"))
