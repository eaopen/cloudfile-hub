"""Actual isolated Redis tests. Native projection/guard remain explicit fixtures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from threading import Event
import unittest
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
        def guard(user_id, epoch):
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
