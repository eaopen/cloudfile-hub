"""Display-only CE tag snapshot; native ORM reads are explicit test doubles."""
import time
from unittest import TestCase
from unittest.mock import patch

from cloudfile_ext.v2 import library_cache, tag_display

RID = '00000000-0000-4000-8000-000000000001'
OTHER = '00000000-0000-4000-8000-000000000002'


def row(pk, path, is_dir=False, repo_id=RID, tag=(7, 'SYS_review', '#f00')):
    parent, name = path.rsplit('/', 1)
    return (pk, tag[0], tag[1], tag[2], repo_id, parent or '/', name, is_dir)


class TagDisplayTests(TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure()

    def setUp(self):
        from django.test import override_settings
        from django.core.cache import cache
        self.override = override_settings(CF_TAG_CACHE_TTL=180, CACHES={'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'cf-tag-test'}})
        self.override.enable()
        self.addCleanup(self.override.disable)
        cache.clear()
        self.library = patch('cloudfile_ext.v2.tag_display.read_library')
        self.page = patch('cloudfile_ext.v2.tag_display.read_page')
        self.read_library, self.read_page = self.library.start(), self.page.start()
        self.addCleanup(self.library.stop)
        self.addCleanup(self.page.stop)

    def test_files_and_directories_are_matched_by_path_and_kind(self):
        self.read_library.return_value = [row(1, '/docs/a.txt'), row(2, '/docs/sub', True),
                                          row(3, '/docs/sub', False)]  # same name, other kind
        result = tag_display.tags_for_entries(RID, '/docs', [('/docs/a.txt', 'file'), ('/docs/sub', 'dir'),
                                                             ('/docs/plain', 'file')])
        self.assertEqual([t['file_tag_id'] for t in result[('/docs/a.txt', 'file')]], [1])
        self.assertEqual([t['file_tag_id'] for t in result[('/docs/sub', 'dir')]], [2])
        self.assertEqual(result[('/docs/plain', 'file')], [])
        self.assertEqual(result[('/docs/a.txt', 'file')][0],
                         dict(file_tag_id=1, repo_tag_id=7, tag_name='SYS_review', tag_color='#f00'))

    def test_only_requested_visible_entries_and_this_library_are_returned(self):
        self.read_library.return_value = [row(1, '/docs/hidden'), row(2, '/docs/a.txt', repo_id=OTHER)]
        result = tag_display.tags_for_entries(RID, '/docs', [('/docs/a.txt', 'file')])
        self.assertEqual(result, {('/docs/a.txt', 'file'): []})

    def test_library_snapshot_is_shared_until_expiry_or_commit_invalidation(self):
        self.read_library.return_value = [row(1, '/a.txt')]
        entries = [('/a.txt', 'file')]
        tag_display.tags_for_entries(RID, '/', entries)
        self.read_library.return_value = []
        self.assertEqual(len(tag_display.tags_for_entries(RID, '/', entries)[entries[0]]), 1)
        self.read_library.assert_called_once()
        with patch('cloudfile_ext.v2.library_cache.time.time', return_value=time.time() + 181):
            self.assertEqual(tag_display.tags_for_entries(RID, '/', entries)[entries[0]], [])
        self.read_library.return_value = [row(1, '/a.txt')]
        library_cache.invalidate(tag_display.NAMESPACE, RID)
        self.assertEqual(len(tag_display.tags_for_entries(RID, '/', entries)[entries[0]]), 1)

    def test_over_budget_library_reads_only_the_page_and_caches_the_marker(self):
        self.read_library.return_value = None
        self.read_page.return_value = [row(5, '/big/x.txt')]
        entries = [('/big/x.txt', 'file'), ('/big/y', 'dir')]
        result = tag_display.tags_for_entries(RID, '/big', entries)
        self.assertEqual([t['file_tag_id'] for t in result[entries[0]]], [5])
        self.read_page.assert_called_once_with(RID, '/big', ['x.txt', 'y'])
        tag_display.tags_for_entries(RID, '/big', entries)
        self.read_library.assert_called_once()

    def test_empty_page_reads_nothing_and_failures_are_not_cached(self):
        self.assertEqual(tag_display.tags_for_entries(RID, '/', []), {})
        self.read_library.assert_not_called()
        self.read_library.side_effect = OSError()
        with self.assertRaises(OSError):
            tag_display.tags_for_entries(RID, '/', [('/a', 'file')])
        self.read_library.side_effect = None
        self.read_library.return_value = [row(1, '/a')]
        self.assertEqual(len(tag_display.tags_for_entries(RID, '/', [('/a', 'file')])[('/a', 'file')]), 1)

    def test_malformed_cache_entry_is_reread(self):
        from django.core.cache import cache
        cache.set('%s:0:%s' % (tag_display.NAMESPACE, RID),
                  {'expires': time.time() + 60, 'data': [['bad']]}, 60)
        self.read_library.return_value = [row(1, '/a')]
        self.assertEqual(len(tag_display.tags_for_entries(RID, '/', [('/a', 'file')])[('/a', 'file')]), 1)
        self.read_library.assert_called_once()
