"""Dependency-light snapshot contract, runnable by cheap source CI."""
from pathlib import Path
from unittest import TestCase

from cloudfile_ext.v2.acl_batch import fingerprint, key_of
from cloudfile_ext.v2.acl_policy import Rule

RID = '00000000-0000-4000-8000-000000000001'


class BatchPureContract(TestCase):
    def test_snapshot_order_version_and_provider(self):
        a = Rule(RID, '/a', 'etech', 'user', 'user', 'uid', 'r')
        b = Rule(RID, '/b', 'etech', 'role', 'role', 'group', 'invisible')
        rows = ((a, 'r1'), (b, 'r2'))
        self.assertEqual(fingerprint(rows), fingerprint(reversed(rows)))
        self.assertNotEqual(fingerprint(rows), fingerprint(((a, 'r3'), (b, 'r2'))))
        self.assertNotEqual(fingerprint(rows), fingerprint(((a, 'r1'),)))
        self.assertEqual(key_of(a), ('/a', 'user', 'user', 'uid'))

    def test_same_library_rules_for_reads_and_writes(self):
        source = (Path(__file__).resolve().parents[1] / 'acl_runtime.py').read_text()
        self.assertIn('rows = library_rules(self.store, repo_id, cache_ttl())', source)
        self.assertIn('self._rule_paths[repo_id] = buckets', source)
        self.assertIn('return [rule for path in ancestors(directory)', source)
        policy = (Path(__file__).resolve().parents[1] / 'acl_http.py').read_text()
        self.assertIn('decision = authority.effective(data[\'repo_id\'], check[\'path\'], check[\'kind\'])', policy)
        self.assertIn('decision.can_read if check[\'action\'] == \'read\' else decision.can_write', policy)

    def test_existing_per_rule_routes_are_still_installed(self):
        urls = (Path(__file__).resolve().parents[3] / 'seahub' / 'urls.py').read_text()
        self.assertIn('directory-rules/\', DirectoryRules.as_view()', urls)
        self.assertIn('library-acl-batch/\', LibraryACLBatch.as_view()', urls)
