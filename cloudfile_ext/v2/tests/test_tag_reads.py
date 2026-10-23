"""Native tag reader behavior with controlled ORM returns: no library-wide query."""
from types import ModuleType, SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch
import sys

from cloudfile_ext.v2 import tag_reads

RID = '00000000-0000-4000-8000-000000000001'


class TagReadsTests(TestCase):
    def _models(self):
        # Synthetic model managers: test batching without a live Seahub database.
        repo = MagicMock()
        legacy = MagicMock()
        repo.objects.filter.return_value.values_list.return_value.order_by.return_value.__getitem__.return_value = [
            (1, 7, 'SYS_review', '#f00', '/docs', 'a.txt', False),
            (2, 8, 'directory', '#0f0', '/docs', 'sub', True),
            (3, 9, 'hidden', '#fff', '/docs', 'hidden', False),
            (4, 10, 'wrong kind', '#fff', '/docs', 'sub', False),
        ]
        legacy.objects.filter.return_value.values_list.return_value.order_by.return_value.__getitem__.return_value = [
            (5, 'Old', '/docs', 'a.txt', False),
            (6, 'Other', '/docs', 'hidden', False),
        ]
        return repo, legacy

    def _modules(self, repo, legacy):
        mod_repo = ModuleType('seahub.file_tags.models')
        mod_repo.FileTags = repo
        mod_tags = ModuleType('seahub.tags.models')
        mod_tags.FileTag = legacy
        mod_tags.FileUUIDMap = SimpleNamespace(md5_repo_id_parent_path=lambda repo_id, parent:
                                               (repo_id + ':' + parent))
        return patch.dict(sys.modules, {'seahub.file_tags.models': mod_repo,
                                        'seahub.tags.models': mod_tags})

    def test_page_and_legacy_label_are_filtered_to_visible_files_and_kinds(self):
        repo, legacy = self._models()
        with self._modules(repo, legacy):
            data = tag_reads.read(RID, [('/docs/a.txt', 'file'), ('/docs/sub', 'dir')])
        self.assertEqual([tag['source'] for tag in data[('/docs/a.txt', 'file')]], ['repo', 'legacy'])
        self.assertTrue(data[('/docs/a.txt', 'file')][1]['read_only'])
        self.assertEqual(data[('/docs/a.txt', 'file')][1]['legacy_tag_id'], 5)
        self.assertNotIn('file_tag_id', data[('/docs/a.txt', 'file')][1])
        self.assertEqual([tag['file_tag_id'] for tag in data[('/docs/sub', 'dir')]], [2])
        self.assertNotIn(('/docs/hidden', 'file'), data)
        repo.objects.filter.assert_called_once()
        legacy.objects.filter.assert_called_once()

    def test_zero_references_avoids_database(self):
        self.assertEqual(tag_reads.read(RID, []), {})

    def test_bounded_references(self):
        with self.assertRaises(ValueError):
            tag_reads.read(RID, [('/docs/%s' % i, 'file') for i in range(1001)])

    def test_two_directories_share_one_batch_per_tag_type(self):
        repo, legacy = self._models()
        with self._modules(repo, legacy):
            values = tag_reads.read(RID, [('/docs/a.txt', 'file'), ('/other/file', 'file')])
        self.assertEqual(len(values), 2)
        self.assertEqual(repo.objects.filter.call_count, 1)
        self.assertEqual(legacy.objects.filter.call_count, 1)
