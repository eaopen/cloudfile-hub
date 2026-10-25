"""Cheap real indexing-cursor regressions, no Seafile/Redis/Meilisearch service."""
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cloudfile_ext.v2.search.worker import Indexer, SearchUnavailable, tick

RID = "a6fbc97c-1000-4000-8000-010101010101"
HEAD_A = "a" * 40
HEAD_B = "b" * 40


class InitialIndexTests(unittest.TestCase):
    def setUp(self):
        self.repo = SimpleNamespace(id=RID, head_cmmt_id=HEAD_A,
                                    is_virtual=False, encrypted=False)
        self.calls = []
        self.first = [SimpleNamespace(obj_name="file-%03d.txt" % n,
                       mode=stat.S_IFREG | 0o644, size=100, mtime=1)
                      for n in range(200)]
        self.last = [SimpleNamespace(obj_name="final.txt",
                     mode=stat.S_IFREG | 0o644, size=100, mtime=1)]

        def page(repo, head, parent, offset, limit):
            self.calls.append((repo, head, parent, offset, limit))
            self.assertEqual((repo, parent, limit), (RID, "/", 200))
            return self.first if offset == 0 else self.last if offset == 200 else []

        self.native = Mock()
        self.native.list_dir_by_commit_and_path.side_effect = page
        self.native.get_repo_list.side_effect = lambda offset, limit: [self.repo] if offset == 0 else []
        self.native.get_repo.side_effect = lambda repo: self.repo
        self.native.diff_commits.return_value = []
        self.client = Mock(index_path="/indexes/cloudfile_files")
        self.client.call.return_value = {"results": []}
        self.tags = patch('cloudfile_ext.v2.search.worker.tag_labels',
                          side_effect=lambda rid, refs: {name: [] for name, kind in refs})
        self.publish = patch.object(Indexer, 'publish', return_value=None)
        self.tags.start()
        self.publish_mock = self.publish.start()
        self.addCleanup(self.tags.stop)
        self.addCleanup(self.publish.stop)

    def test_slice_is_bounded_and_mutates_cursor_only_after_publish(self):
        worker = Indexer(self.client, self.native)
        initial = {"head": HEAD_A, "pending": [{"path": "/", "offset": 0}]}
        self.assertFalse(worker.scan_slice(self.repo, initial, max_pages=1))
        self.assertEqual(initial['pending'], [{"path": "/", "offset": 200}])
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(worker.scan_slice(self.repo, initial, max_pages=1))
        self.assertEqual(initial['pending'], [])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.publish_mock.call_count, 2)

    def test_meilisearch_failure_does_not_advance_the_cursor(self):
        self.publish_mock.side_effect = SearchUnavailable('Meili failed')
        progress = {"head": HEAD_A, "pending": [{"path": "/", "offset": 0}]}
        with self.assertRaises(SearchUnavailable):
            Indexer(self.client, self.native).scan_slice(self.repo, progress, max_pages=1)
        self.assertEqual(progress["pending"], [{"path": "/", "offset": 0}])

    def test_restart_resumes_pinned_head_then_catches_up(self):
        django = types.ModuleType("django")
        db = types.ModuleType("django.db")
        db.close_old_connections = lambda: None
        django.db = db
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                sys.modules, {'django': django, 'django.db': db}):
            checkpoint = str(Path(directory) / "index.json")
            tick(self.client, self.native, checkpoint, pages_per_repo=1)
            saved = json.loads(Path(checkpoint).read_text())
            self.assertEqual(saved[RID]['initial']['pending'],
                             [{"path": "/", "offset": 200}])

            self.repo.head_cmmt_id = HEAD_B
            tick(self.client, self.native, checkpoint, pages_per_repo=1)
            saved = json.loads(Path(checkpoint).read_text())
            self.assertEqual(saved[RID]['head'], HEAD_A)
            self.assertNotIn('initial', saved[RID])
            self.assertEqual({head for _, head, *_ in self.calls}, {HEAD_A})

            with patch.object(Indexer, "sweep", return_value=""):
                tick(self.client, self.native, checkpoint, pages_per_repo=1)
            saved = json.loads(Path(checkpoint).read_text())
            self.assertEqual(saved[RID]['head'], HEAD_B)
            self.native.diff_commits.assert_called_with(RID, HEAD_A, HEAD_B, 1)


class WorkerRegistrationSourceTests(unittest.TestCase):
    def test_directory_catalog_has_no_cloudfile_scheduler(self):
        source = (Path(__file__).resolve().parents[2] / 'apps.py').read_text()
        self.assertNotIn('directory-entities', source)
        self.assertNotIn('register_periodic_task', source)
        self.assertNotIn('_register_directory_catalog', source)

    def test_external_admin_api_keeps_entity_sync(self):
        source = (Path(__file__).resolve().parents[2] / 'http.py').read_text()
        self.assertIn('class CatalogSync(', source)
        self.assertIn('result = sync_entity_catalog()', source)

    def test_v2_search_stays_independent(self):
        source = (Path(__file__).resolve().parents[1] / 'search/worker.py').read_text()
        self.assertIn('def scan_slice(', source)
        self.assertIn('time.sleep(interval)', source)


if __name__ == '__main__':
    unittest.main()
