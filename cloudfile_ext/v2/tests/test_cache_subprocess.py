"""Real subprocess tests. Redis test needs an isolated CF_V2_REDIS_URL endpoint."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import TestCase, skipUnless
from uuid import uuid4


class CacheSubprocessTests(TestCase):
    def probe(self, action, repo, value=None):
        env = dict(os.environ)
        root = Path(__file__).resolve().parents[3]
        args = [sys.executable, '-m', 'cloudfile_ext.v2.tests.cache_probe', action, repo]
        if value is not None:
            args.append(value)
        result = subprocess.run(args, capture_output=True, text=True, cwd=root, env=env, timeout=15,
                                check=True)
        return json.loads(result.stdout.strip())

    def test_outer_transaction_rollback_does_not_invalidate(self):
        # A real SQLite transaction (not a mocked on_commit callback).
        result = self.probe('callback', str(uuid4()))
        self.assertTrue(result['rollback_kept_generation'])
        self.assertTrue(result['commit_switched_generation'])

    @skipUnless(os.environ.get('CF_V2_REDIS_URL'), 'isolated Redis URL required')
    def test_two_independent_workers_share_snapshot_and_invalidation(self):
        repo = str(uuid4())
        first = self.probe('read', repo, 'allow')
        second = self.probe('read', repo, 'deny')
        self.assertNotEqual(first['pid'], second['pid'])
        self.assertEqual(second['value'], ['allow'])
        switch = self.probe('invalidate', repo)
        self.assertTrue(switch['invalidated'])
        third = self.probe('read', repo, 'deny')
        self.assertEqual(third['value'], ['deny'])
