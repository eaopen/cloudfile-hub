"""Same authority for native members and directory-only virtual views."""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from cloudfile_ext.v2.acl_policy import Principal, Rule, resolve
from cloudfile_ext.v2.acl_runtime import Authority

RID = '00000000-0000-4000-8000-000000000001'
P = Principal('etech', 'uid')


class RuntimeTests(TestCase):
    def setUp(self):
        # Policy behavior only; LibraryCacheTests owns cross-request caching.
        ttl = patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=0)
        ttl.start()
        self.addCleanup(ttl.stop)

    def authority(self, base=None, share=True, permission='rw', inherit=True):
        rule = Rule(RID, '/projects/shared', 'etech', 'user', 'user', 'uid', permission, inherit, share)
        rules = Mock()
        rules.candidates.side_effect = lambda repo, path, principal: [(rule, 'v')] if path.startswith(rule.path) else []
        # Whole-library rows include other subjects/providers; Authority filters them.
        foreign = Rule(RID, '/projects', 'other-idp', 'user', 'user', 'uid', 'invisible')
        rules.library.return_value = (rule, foreign)
        rules.shared.return_value = [(rule, 'v')]
        api = Mock()
        api.get_repo.return_value = SimpleNamespace(is_virtual=False, version=1)
        api.get_repo_status.return_value = 0
        api.check_permission.return_value = base
        api.get_dir_id_by_path.return_value = 'directory-object'
        return Authority('native@auth.local', principal=P, rules=rules, api=api)

    def test_directory_only_access_requires_both_share_and_permission(self):
        auth = self.authority()
        for path in ('/projects/shared', '/projects/shared/sub'):
            result = auth.effective(RID, path)
            self.assertTrue(result.can_read)
            self.assertEqual(result.qualified_root, '/projects/shared')
        self.assertTrue(auth.effective(RID, '/projects/shared/file', 'file').can_write)
        for path in ('/', '/projects', '/projects/sibling', '/projects/shared-other'):
            self.assertFalse(auth.effective(RID, path).can_read)
        self.assertFalse(self.authority(share=False).effective(RID, '/projects/shared').can_read)

    def test_library_member_keeps_library_root(self):
        auth = self.authority(base='r')
        self.assertEqual(auth.effective(RID, '/').qualified_root, '/')
        self.assertEqual(auth.effective(RID, '/projects/shared').qualified_root, '/')
        self.assertTrue(auth.effective(RID, '/projects/shared').can_write)

    def test_listing_is_bounded_and_root_is_not_parent_corridor(self):
        auth = self.authority()
        auth.api.list_dir_by_dir_id.return_value = [SimpleNamespace(obj_name='file.txt', mode=0o100644)]
        result = auth.entries(RID, '/projects/shared')
        self.assertEqual(result['root_path'], '/projects/shared')
        self.assertEqual(result['data'][0]['path'], '/projects/shared/file.txt')
        auth.api.list_dir_by_dir_id.assert_called_once_with(RID, 'directory-object', 0, 51)
        for path in ('/', '/projects', '/projects/sibling'):
            with self.assertRaises(PermissionError):
                auth.entries(RID, path)

    def test_hard_readonly_and_denial_use_the_same_algorithm(self):
        auth = self.authority()
        auth.api.get_repo_status.return_value = 1
        self.assertTrue(auth.effective(RID, '/projects/shared').can_read)
        self.assertFalse(auth.effective(RID, '/projects/shared').can_write)
        auth = self.authority(base='rw', share=False, permission='invisible')
        self.assertFalse(auth.effective(RID, '/projects/shared').can_read)

    def test_stale_or_inactive_principal_denied(self):
        auth = self.authority()
        auth.principal = Principal('etech', 'uid', ready=False)
        self.assertFalse(auth.effective(RID, '/projects/shared').can_read)
        auth.principal = Principal('etech', 'uid', active=False)
        self.assertFalse(auth.effective(RID, '/projects/shared').can_write)

    def test_subject_share_does_not_grant_everyone(self):
        auth = self.authority()
        auth.principal = Principal('etech', 'another-user')
        self.assertFalse(auth.effective(RID, '/projects/shared').can_read)
        self.assertEqual(auth.shared_roots(), [])

    def test_listing_hides_denied_child_with_one_library_read(self):
        auth = self.authority()
        allow = auth.store.shared.return_value[0][0]
        denied = Rule(RID, '/projects/shared/secret', 'etech', 'user', 'user', 'uid', 'invisible')
        auth.store.library.return_value = (allow, denied)
        auth.api.list_dir_by_dir_id.return_value = [SimpleNamespace(obj_name=name, mode=0o040755)
                                                    for name in ('a', 'b', 'secret')]
        result = auth.entries(RID, '/projects/shared')
        self.assertEqual([item['name'] for item in result['data']], ['a', 'b'])
        auth.store.library.assert_called_once_with(RID)
        auth.store.candidates.assert_not_called()

    def test_library_over_budget_falls_back_to_directory_candidates(self):
        auth = self.authority()
        auth.store.library.return_value = None
        self.assertTrue(auth.effective(RID, '/projects/shared/file', 'file').can_write)
        self.assertFalse(auth.effective(RID, '/projects/sibling').can_read)
        self.assertEqual(auth.store.candidates.call_count, 2)
        auth.store.library.assert_called_once()


class LibraryCacheTests(TestCase):
    """Whole-library rule cache shared by every user for at most the TTL."""
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure()

    def setUp(self):
        from django.test import override_settings
        from django.core.cache import cache
        self.override = override_settings(CF_ACL_CACHE_TTL=180, CACHES={'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'cf-acl-library-test'}})
        self.override.enable()
        cache.clear()
        # These tests exercise cache storage with LocMem intentionally; production
        # rejects it. Override the TTL here to verify snapshot behavior itself.
        self.ttl_override = patch('cloudfile_ext.v2.acl_runtime.cache_ttl', return_value=180)
        self.ttl_override.start()
        self.addCleanup(self.ttl_override.stop)
        self.denied = Rule(RID, '/projects/shared', 'etech', 'user', 'user', 'uid', 'invisible')

    def tearDown(self):
        self.override.disable()

    def test_rules_are_shared_until_expiry(self):
        import time
        first = RuntimeTests().authority()
        self.assertTrue(first.effective(RID, '/projects/shared/file', 'file').can_write)
        second = RuntimeTests().authority()
        second.store.library.return_value = (self.denied,)
        self.assertTrue(second.effective(RID, '/projects/shared/other', 'file').can_write)
        second.store.library.assert_not_called()
        third = RuntimeTests().authority()
        third.store.library.return_value = (self.denied,)
        with patch('cloudfile_ext.v2.library_cache.time.time', return_value=time.time() + 181):
            self.assertFalse(third.effective(RID, '/projects/shared/other', 'file').can_read)
        third.store.library.assert_called_once_with(RID)

    def test_committed_write_invalidates_library_immediately(self):
        from cloudfile_ext.v2.acl_runtime import invalidate_library
        RuntimeTests().authority().effective(RID, '/projects/shared')
        invalidate_library(RID)
        fresh = RuntimeTests().authority()
        fresh.store.library.return_value = (self.denied,)
        self.assertFalse(fresh.effective(RID, '/projects/shared').can_read)
        fresh.store.library.assert_called_once()

    def test_over_budget_marker_is_cached(self):
        first = RuntimeTests().authority()
        first.store.library.return_value = None
        self.assertTrue(first.effective(RID, '/projects/shared').can_read)
        second = RuntimeTests().authority()
        self.assertTrue(second.effective(RID, '/projects/shared').can_read)
        second.store.library.assert_not_called()
        second.store.candidates.assert_called_once()

    def test_cache_outage_recomputes_and_hard_readonly_still_applies(self):
        with patch('django.core.cache.cache.get', side_effect=OSError()), \
                patch('django.core.cache.cache.set', side_effect=OSError()):
            auth = RuntimeTests().authority()
            auth.api.get_repo_status.return_value = 1
            self.assertFalse(auth.effective(RID, '/projects/shared/file', 'file').can_write)
            self.assertTrue(auth.effective(RID, '/projects/shared/file', 'file').can_read)
            auth.store.library.assert_called_once()

    def test_sql_failure_is_not_cached_or_granted(self):
        auth = RuntimeTests().authority()
        auth.store.library.side_effect = OSError()
        with self.assertRaises(OSError):
            auth.effective(RID, '/projects/shared')

    def test_refill_started_before_invalidation_cannot_poison_new_generation(self):
        from cloudfile_ext.v2.acl_runtime import invalidate_library
        from django.core.cache import cache
        from cloudfile_ext.v2 import acl_runtime
        rules = Mock()
        first = (Rule(RID, '/projects', 'etech', 'user', 'user', 'uid', 'rw'),)
        second = (self.denied,)
        def slow_read(_repo):
            # Simulate a writer committing after this reader chose generation 0,
            # but before the old SQL response fills its cache entry.
            invalidate_library(RID)
            return first
        rules.library.side_effect = slow_read
        self.assertEqual(acl_runtime.library_rules(rules, RID, 180), first)
        self.assertIsNotNone(cache.get(acl_runtime.NAMESPACE + ':0:' + RID))
        rules.library.side_effect = None
        rules.library.return_value = second
        self.assertEqual(acl_runtime.library_rules(rules, RID, 180), second)
        self.assertEqual(rules.library.call_count, 2)

    def test_cache_invalidation_failure_is_bounded_by_original_ttl(self):
        import time
        from django.core.cache import cache
        from cloudfile_ext.v2 import acl_runtime
        rules = Mock()
        first = (Rule(RID, '/projects', 'etech', 'user', 'user', 'uid', 'rw'),)
        rules.library.return_value = first
        self.assertEqual(acl_runtime.library_rules(rules, RID, 180), first)
        original_set = cache.set
        def deny_generation(key, value, timeout=None, **kwargs):
            if ':gen:' in key:
                raise OSError('redis unavailable for invalidation')
            return original_set(key, value, timeout, **kwargs)
        with patch('django.core.cache.cache.set', side_effect=deny_generation):
            acl_runtime.invalidate_library(RID)  # must not break rule write
        rules.library.return_value = (self.denied,)
        self.assertEqual(acl_runtime.library_rules(rules, RID, 180), first)
        with patch('cloudfile_ext.v2.library_cache.time.time', return_value=time.time() + 181):
            self.assertEqual(acl_runtime.library_rules(rules, RID, 180), (self.denied,))
        self.assertEqual(rules.library.call_count, 2)

    def protected(self, rows_by_repo, repo=None):
        from cloudfile_ext.v2.acl_runtime import protected
        rules = Mock()
        rules.library.side_effect = lambda repo_id: rows_by_repo.get(repo_id, ())
        with patch('cloudfile_ext.v2.acl_runtime.store', return_value=rules):
            return protected(RID, repo or SimpleNamespace(is_virtual=False)), rules

    def test_download_protection_check_is_served_from_the_library_snapshot(self):
        from cloudfile_ext.v2.acl_runtime import invalidate_library
        self.assertFalse(self.protected({})[0])
        # Warm snapshot answers without SQL until a committed write switches it.
        result, rules = self.protected({RID: (self.denied,)})
        self.assertFalse(result)
        rules.library.assert_not_called()
        invalidate_library(RID)
        self.assertTrue(self.protected({RID: (self.denied,)})[0])
        invalidate_library(RID)
        self.assertTrue(self.protected({RID: None})[0])  # over budget still protects

    def test_virtual_repository_checks_its_origin(self):
        origin = '00000000-0000-4000-8000-000000000002'
        repo = SimpleNamespace(is_virtual=True, origin_repo_id=origin)
        rule = Rule(origin, '/x', 'etech', 'user', 'user', 'uid', 'invisible')
        self.assertTrue(self.protected({origin: (rule,)}, repo)[0])
        from cloudfile_ext.v2.acl_runtime import protected
        with self.assertRaises(Exception):
            protected(RID, None)


class CacheBackendSafetyTests(TestCase):
    def test_local_or_dummy_cache_disables_cross_request_acl_cache(self):
        from django.test import override_settings
        from cloudfile_ext.v2.acl_runtime import cache_ttl
        for backend in ('django.core.cache.backends.locmem.LocMemCache',
                        'django.core.cache.backends.dummy.DummyCache'):
            with override_settings(CF_ACL_CACHE_TTL=180, CACHES={'default': {
                    'BACKEND': backend, 'LOCATION': 'cache-safety-test'}}):
                self.assertEqual(cache_ttl(), 0)

    def test_shared_redis_cache_keeps_bounded_ttl(self):
        from django.test import override_settings
        from cloudfile_ext.v2.acl_runtime import cache_ttl
        with override_settings(CF_ACL_CACHE_TTL=180, CACHES={'default': {
                'BACKEND': 'django.core.cache.backends.redis.RedisCache',
                'LOCATION': 'redis://127.0.0.1:16394'}}):
            self.assertEqual(cache_ttl(), 180)
