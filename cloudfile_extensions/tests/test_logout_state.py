"""Isolated Redis protocol regressions; not IdP logout/session deletion proof."""
import hashlib
import os
import unittest
from unittest.mock import Mock
from uuid import uuid4
from redis.exceptions import RedisError

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.logout_state import LogoutStates


@unittest.skipUnless(os.environ.get("CF_TEST_REDIS_PORT"), "requires isolated CloudFile test Redis")
class LogoutRedisTests(unittest.TestCase):
    def setUp(self):
        import redis
        self.redis = redis.Redis(host=os.environ.get("CF_TEST_REDIS_HOST", "127.0.0.1"),
            port=int(os.environ["CF_TEST_REDIS_PORT"]))
        self.prefix = "cf:test:" + uuid4().hex + ":"
        self.states = LogoutStates(self.redis, issuer="https://idp.invalid/", client_id="cloudfile", prefix=self.prefix)

    def tearDown(self):
        keys = list(self.redis.scan_iter(match=self.prefix + "*"))
        if keys:
            self.redis.delete(*keys)
        self.redis.close()

    def test_fixed_ttl_digest_storage_and_single_use(self):
        state, binding = self.states.issue()
        key = self.states.key(state)
        self.assertNotIn(state, key)
        self.assertEqual(self.redis.get(key), hashlib.sha256(binding.encode()).hexdigest().encode())
        self.assertTrue(0 < self.redis.pttl(key) <= 300000)
        self.states.consume(state, binding)
        with self.assertRaises(ContractError) as caught:
            self.states.consume(state, binding)
        self.assertEqual(caught.exception.status, 401)

    def test_wrong_browser_and_client_do_not_consume_correct_state(self):
        state, binding = self.states.issue()
        with self.assertRaises(ContractError):
            self.states.consume(state, "z" * 43)
        other = LogoutStates(self.redis, issuer="https://idp.invalid/", client_id="other", prefix=self.prefix)
        with self.assertRaises(ContractError):
            other.consume(state, binding)
        self.states.consume(state, binding)

    def test_expired_state_rejected_without_sleep(self):
        state, binding = self.states.issue()
        self.redis.pexpire(self.states.key(state), 0)
        with self.assertRaises(ContractError) as caught:
            self.states.consume(state, binding)
        self.assertEqual(caught.exception.status, 401)


class LogoutFaultTests(unittest.TestCase):
    def test_redis_failure_never_falls_back_to_cookie_only(self):
        redis = Mock()
        redis.eval.side_effect = RedisError("private transport details")
        states = LogoutStates(redis, issuer="https://idp.invalid/", client_id="cloudfile")
        with self.assertRaises(ContractError) as caught:
            states.consume("s" * 43, "b" * 43)
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("private", str(caught.exception))
        redis.set.side_effect = RedisError("private transport details")
        with self.assertRaises(ContractError):
            states.issue()
