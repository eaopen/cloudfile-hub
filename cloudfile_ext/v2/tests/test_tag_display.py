"""Directory page native CE tags, with search-compatible read-only legacy display."""
from unittest import TestCase
from unittest.mock import patch

from cloudfile_ext.v2 import tag_display

RID = '00000000-0000-4000-8000-000000000001'


class TagDisplayTests(TestCase):
    def setUp(self):
        self.page = patch('cloudfile_ext.v2.tag_display.read_page')
        self.read_page = self.page.start()
        self.addCleanup(self.page.stop)

    def test_authorized_page_returns_batched_repo_and_legacy_tags(self):
        entries = [('/docs/a.txt', 'file'), ('/docs/sub', 'dir')]
        self.read_page.return_value = {
            entries[0]: [dict(source='repo', file_tag_id=1, repo_tag_id=7, tag_name='SYS_review',
                              tag_color='#f00')],
            entries[1]: [dict(source='legacy', legacy_tag_id=9, tag_name='old', read_only=True)],
        }
        result = tag_display.tags_for_entries(RID, '/docs', entries)
        self.assertEqual(result[entries[0]][0]['repo_tag_id'], 7)
        self.assertTrue(result[entries[1]][0]['read_only'])
        self.read_page.assert_called_once_with(RID, '/docs', entries)

    def test_each_page_reads_fresh_tags_without_cache_or_signal(self):
        entries = [('/docs/a.txt', 'file')]
        self.read_page.return_value = {entries[0]: [dict(tag_name='now')]}
        self.assertEqual(tag_display.tags_for_entries(RID, '/docs', entries)[entries[0]][0]['tag_name'], 'now')
        self.read_page.return_value = {entries[0]: []}
        self.assertEqual(tag_display.tags_for_entries(RID, '/docs', entries)[entries[0]], [])
        self.assertEqual(self.read_page.call_count, 2)
        self.assertFalse(hasattr(tag_display, 'connect_invalidation'))
        self.assertFalse(hasattr(tag_display, 'read_library'))

    def test_empty_and_invalid_references_do_not_query(self):
        self.assertEqual(tag_display.tags_for_entries(RID, '/docs', []), {})
        for entries in ([('/other/a', 'file')], [('/docs/a', 'unknown')],
                        [('/docs/a', 'file')] * 101):
            with self.assertRaises(ValueError):
                tag_display.tags_for_entries(RID, '/docs', entries)
        self.read_page.assert_not_called()

    def test_read_failure_is_not_cached(self):
        self.read_page.side_effect = OSError('database unavailable')
        with self.assertRaises(OSError):
            tag_display.tags_for_entries(RID, '/docs', [('/docs/a', 'file')])
        self.read_page.side_effect = None
        self.read_page.return_value = {('/docs/a', 'file'): []}
        self.assertEqual(tag_display.tags_for_entries(RID, '/docs', [('/docs/a', 'file')]),
                         {('/docs/a', 'file'): []})
