"""Set CF_TEST_MEILI_URL to run against a disposable local Meilisearch."""
import os
import stat
import unittest
from types import SimpleNamespace
from uuid import uuid4

from cloudfile_ext.v2.search.client import ExistingMeiliIndex
from cloudfile_ext.v2.search.numbers import is_number_query, number_grams
from cloudfile_ext.v2.search.worker import Indexer, backfill_number_search, confirm


class DrawingSearchTests(unittest.TestCase):
    def test_code_detection_and_substrings(self):
        for query in ('3K70', 'tp3k70', '01.0101', '6K70-01', '0101'):
            self.assertTrue(is_number_query(query))
        for query in ('工艺', 'report', '设计 3K70', '01'):
            self.assertFalse(is_number_query(query))
        self.assertLessEqual(set(number_grams('3k70', [])), set(number_grams('TP3K70图纸', [])))
        self.assertNotIn('3k7', number_grams('TP6K70图纸', []))

    @unittest.skipUnless(os.getenv('CF_TEST_MEILI_URL'), 'requires local Meilisearch')
    def test_existing_and_new_drawings(self):
        index = 'drawing_test_' + uuid4().hex
        client = ExistingMeiliIndex(os.environ['CF_TEST_MEILI_URL'], index=index)
        confirm(client, client.call('POST', '/indexes', dict(uid=index, primaryKey='id')))
        self.addCleanup(lambda: confirm(client, client.call('DELETE', client.index_path)))
        confirm(client, client.call('PATCH', client.index_path + '/settings', dict(
            searchableAttributes=['name', 'tags'], filterableAttributes=['repo_id', 'dirs', 'path'])))
        indexer = Indexer(client, None)
        repo = SimpleNamespace(id='repo')
        root = '/部件设计室'
        dongming = 'TP3K70-01_DongMing_EN5-X1'
        singapore = 'TP6K70-01_Singapore_HE5-X2'
        pdf = '18.TP6K70-01.0101.pdf'
        paths = [(root + '/' + dongming, []), (root + '/' + singapore, []),
                 (root + '/' + pdf, []), (root + '/说明.pdf', ['ZT8Q91']),
                 ('/其他/' + dongming, []), (root + '/普通文档', [])]
        docs = []
        for path, tags in paths:
            entry = SimpleNamespace(mode=stat.S_IFDIR if '.' not in path else stat.S_IFREG, size=3, mtime=1)
            doc = indexer.upsert(repo, path, entry, {path: [None, tags]})
            del doc['number_grams']
            docs.append(doc)
        indexer.publish(docs)
        backfill_number_search(client)
        backfill_number_search(client)
        for query, expected in [('3K70', dongming), ('TP3K70', dongming), ('6k70-01.0101', pdf),
                                ('8q91', '说明.pdf'), ('普通文档', '普通文档')]:
            hits = client.page(repo.id, root, query, 0, 50)
            self.assertEqual([hit['path'] for hit in hits], [root + '/' + expected])
            if query == '8q91':
                self.assertEqual(hits[0]['matched_tags'], ['ZT8Q91'])
            else:
                self.assertTrue(hits[0]['text_match'])
        results = [client.page(repo.id, root, 'TP6K70', offset, 1)[0]['path'] for offset in (0, 1)]
        self.assertEqual(set(results), {root + '/' + singapore, root + '/' + pdf})
        acl = '(NOT path = "' + root + '/' + dongming + '")'
        self.assertEqual(client.page(repo.id, root, '3K70', 0, 50, acl_filter=acl), [])
        fresh = root + '/泵组AB42Z91.dwg'
        indexer.publish([indexer.upsert(repo, fresh, entry, {})])
        self.assertEqual(client.page(repo.id, root, '42z9', 0, 10)[0]['path'], fresh)
