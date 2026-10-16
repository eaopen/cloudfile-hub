"""Existing-index protocol and commit catch-up regression checks."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cloudfile_ext.v2.search.client import ExistingMeiliIndex, SearchUnavailable, SearchWindowExceeded, checked_reference
from cloudfile_ext.v2.search.worker import Indexer, confirm, doc_id

RID = 'a6fbc97c-1000-4000-8000-010101010101'


class ExistingIndexTests(unittest.TestCase):
    def client(self, hits, **extra):
        client = ExistingMeiliIndex('http://meili:7700')
        client.call = Mock(side_effect=[dict(hits=hits, **extra), {'maxTotalHits': 1000}])
        return client

    def test_exact_subtree_and_cross_repo_are_rejected(self):
        for path, repo in [('/AB/file', RID), ('/A/../B', RID), ('/A/file', 'other')]:
            with self.subTest(path=path, repo=repo), self.assertRaises(SearchUnavailable):
                checked_reference(dict(repo_id=repo, path=path, object_type='file'), RID, '/A')

    def test_filters_are_quoted_and_totals_are_not_returned(self):
        hit = dict(repo_id=RID, path='/设计/a.txt', object_type='file', tags=['工艺'],
                   _formatted={'tags': ['<em>工艺</em>'], 'path': '/设计/a.txt'})
        client = self.client([hit], estimatedTotalHits=999)
        result = client.page(RID, '/设计', '工艺', 0, 51)
        payload = client.call.call_args_list[0].args[2]
        self.assertIn('dirs IN ["设计"]'.replace('设计', '/设计'), payload['filter'])
        self.assertEqual(result[0]['matched_tags'], ['工艺'])
        self.assertFalse(result[0]['text_match'])
        self.assertNotIn('estimatedTotalHits', result[0])

    def test_small_exact_tail_is_not_confused_with_index_cap(self):
        hits = [dict(repo_id=RID, path='/A.txt', object_type='file')]*50
        self.assertEqual(len(self.client(hits, estimatedTotalHits=100).page(RID, '/', 'A', 50, 51)), 50)
        with self.assertRaises(SearchWindowExceeded):
            self.client(hits, estimatedTotalHits=1000).page(RID, '/', 'A', 950, 51)

    def test_keyword_matches_basename_and_tags_without_searching_parent_path(self):
        hit = dict(repo_id=RID, path='/其他/科室文件.txt', name='科室文件.txt', object_type='file',
                   _formatted={'name': '<em>科室文件</em>.txt'})
        client = self.client([hit])
        result = client.page(RID, '/其他', '科室文件', 0, 51)
        payload = client.call.call_args_list[0].args[2]
        self.assertEqual(payload['attributesToSearchOn'], ['name', 'tags'])
        self.assertEqual(payload['attributesToHighlight'], ['name', 'tags'])
        self.assertIn('name', payload['attributesToRetrieve'])
        self.assertTrue(result[0]['text_match'])

    def test_parent_path_highlight_cannot_count_as_a_name_match(self):
        hit = dict(repo_id=RID, path='/科室文件/其他.txt', name='其他.txt', object_type='file',
                   _formatted={'name': '其他.txt', 'path': '/<em>科室文件</em>/其他.txt'})
        result = self.client([hit]).page(RID, '/', '科室文件', 0, 51)
        self.assertFalse(result[0]['text_match'])

    def test_indexed_filters_quote_tag_and_validate_kind_and_extension(self):
        hit = dict(repo_id=RID, path='/设计/工艺.pdf', name='工艺.pdf',
                   object_type='file', tags=['技术/工艺'],
                   _formatted={'name': '<em>工艺</em>.pdf'})
        client = self.client([hit], estimatedTotalHits=1)
        items = client.page(RID, '/设计', '工艺', 0, 51,
                            kind='file', extension='.PDF', tag='技术/工艺')
        self.assertEqual(len(items), 1)
        payload = client.call.call_args_list[0].args[2]
        self.assertIn('object_type = "file"', payload['filter'])
        self.assertIn('extension = "pdf"', payload['filter'])
        self.assertIn('tags = "技术/工艺"', payload['filter'])
        self.assertEqual(payload['attributesToSearchOn'], ['name', 'tags'])
        self.assertEqual(client.call.call_count, 2)

    def test_directory_filter_uses_both_native_kind_spellings(self):
        hit = dict(repo_id=RID, path='/设计/文件夹', name='文件夹',
                   object_type='folder', tags=[], _formatted={'name': '<em>文件夹</em>'})
        client = self.client([hit], estimatedTotalHits=1)
        self.assertEqual(len(client.page(RID, '/设计', '文件夹', 0, 51, kind='dir')), 1)
        self.assertIn('object_type IN ["dir","folder"]', client.call.call_args_list[0].args[2]['filter'])

    def test_filter_rejections_happen_before_any_search(self):
        client = ExistingMeiliIndex('http://meili:7700')
        client.call = Mock()
        for kwargs in (dict(kind='admin'), dict(extension='../../txt'),
                       dict(extension='pdf OR 1=1'), dict(tag=' 工艺'),
                       dict(tag='invalid' + chr(0)), dict(kind='dir', extension='pdf')):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                client.page(RID, '/', 'abc', 0, 51, **kwargs)
        client.call.assert_not_called()

    def test_existing_index_mismatch_rejected_without_publishing_hits(self):
        client = self.client([dict(repo_id=RID, path='/A/a.txt',
                                   object_type='file', tags=[])], estimatedTotalHits=1)
        with self.assertRaises(SearchUnavailable):
            client.page(RID, '/', 'a', 0, 51, kind='file', extension='pdf')

    def test_pagination_settings_only_fetched_once_per_search_client(self):
        client = ExistingMeiliIndex('http://meili:7700')
        client.call = Mock(side_effect=[
            {'hits': [], 'estimatedTotalHits': 0},
            {'maxTotalHits': 1000},
            {'hits': [], 'estimatedTotalHits': 0}
        ])
        client.page(RID, '/', 'a', 0, 51)
        client.page(RID, '/', 'b', 0, 51)
        self.assertEqual([call.args[0] for call in client.call.call_args_list],
                         ['POST', 'GET', 'POST'])

    def test_untrusted_endpoint_and_index_are_rejected(self):
        for url in ('file:///tmp/index', 'http://user:password@host', 'http://host/path'):
            with self.assertRaises(ValueError):
                ExistingMeiliIndex(url)
        with self.assertRaises(ValueError):
            ExistingMeiliIndex('http://meili', index='../index')


class CatchupTests(unittest.TestCase):
    def test_failed_or_mismatched_task_is_not_acknowledged(self):
        client = Mock(index_path='/indexes/cloudfile_files')
        for task in ({'uid': 1, 'indexUid': 'cloudfile_files', 'status': 'failed'},
                     {'uid': 1, 'indexUid': 'wrong', 'status': 'succeeded'}):
            client.call.return_value = task
            with self.assertRaises(SearchUnavailable):
                confirm(client, {'taskUid': 1})

    def test_new_library_scans_without_deleting_existing_index(self):
        client, native = Mock(), Mock()
        repo = SimpleNamespace(id=RID, head_cmmt_id='new')
        native.get_repo.return_value = repo
        indexer = Indexer(client, native)
        indexer.baseline = Mock(return_value=None)
        indexer.scan = Mock()
        indexer.remove = Mock()
        with patch('cloudfile_ext.v2.search.worker.tag_snapshot', return_value={}):
            saved = indexer.reconcile(repo, None, 0)
        indexer.scan.assert_called_once_with(repo, '/', {})
        indexer.remove.assert_not_called()
        self.assertEqual(saved['head'], 'new')

    def test_move_deletes_old_subtree_and_refreshes_new_path(self):
        client, native = Mock(), Mock()
        repo = SimpleNamespace(id=RID, head_cmmt_id='new')
        native.get_repo.return_value = repo
        native.diff_commits.return_value = [SimpleNamespace(status='mov', name='A', new_name='B')]
        indexer = Indexer(client, native)
        indexer.remove, indexer.refresh = Mock(), Mock()
        with patch('cloudfile_ext.v2.search.worker.tag_snapshot', return_value={}):
            indexer.reconcile(repo, {'head': 'old', 'tags': {}}, 0)
        indexer.remove.assert_called_once_with(RID, '/A')
        indexer.refresh.assert_called_once_with(repo, '/B', {})

    def test_changed_head_does_not_acknowledge_checkpoint(self):
        native = Mock()
        native.diff_commits.return_value = []
        native.get_repo.return_value = SimpleNamespace(head_cmmt_id='changed')
        with patch('cloudfile_ext.v2.search.worker.tag_snapshot', return_value={}), self.assertRaises(SearchUnavailable):
            Indexer(Mock(), native).reconcile(SimpleNamespace(id=RID, head_cmmt_id='new'), {'head': 'old'}, 0)

    def test_document_ids_preserve_existing_format(self):
        self.assertEqual(doc_id(RID, '/members.xlsx'), RID+'-6809ecaf294c5dbd40e64eb8962f86d4470f784b')
