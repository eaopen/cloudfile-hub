from unittest import TestCase
from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.search.cursor import SearchCursorStore


class SearchCursorTest(TestCase):
    def setUp(self):
        self.redis = Mock()
        self.redis.set.return_value = True
        self.store = SearchCursorStore(self.redis, secret=b"s" * 32, clock=lambda: 1000)
        self.scope = dict(user_id="employee", context_epoch="epoch", policy_revision="policy", index_generation="index", query={"q": "drawing"})

    def test_cursor_contains_no_offset_identity_or_query(self):
        token = self.store.issue(scope=self.scope, offset=100)
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        self.redis.get.return_value = self.redis.set.call_args.args[1]
        self.assertEqual(self.store.resolve(token, scope=self.scope), (100, 1300))
        self.assertEqual(self.redis.set.call_args.kwargs, dict(ex=300, nx=True))

    def test_changed_subject_epoch_policy_index_or_query_rejected(self):
        token = self.store.issue(scope=self.scope, offset=100)
        self.redis.get.return_value = self.redis.set.call_args.args[1]
        for name in self.scope:
            changed = {**self.scope, name: {"q": "other"} if name == "query" else "other"}
            with self.assertRaises(ContractError) as caught:
                self.store.resolve(token, scope=changed)
            self.assertEqual(caught.exception.code, "INVALID_CURSOR")

    def test_redis_failure_is_not_a_new_first_page(self):
        self.redis.get.side_effect = RuntimeError("unavailable")
        with self.assertRaises(ContractError) as caught:
            self.store.resolve("a" * 64, scope=self.scope)
        self.assertEqual(caught.exception.code, "SEARCH_UNAVAILABLE")

    def test_continuation_does_not_extend_expiry(self):
        self.store.issue(scope=self.scope, offset=200, expires_at=1100)
        self.assertEqual(self.redis.set.call_args.kwargs["ex"], 100)
