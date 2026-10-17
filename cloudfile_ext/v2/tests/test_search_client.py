"""Existing-index protocol and commit catch-up regression checks."""
import unittest
from types import ModuleType, SimpleNamespace
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

    def test_acl_filter_is_conjoined_and_index_cap_is_read_once(self):
        hit = dict(repo_id=RID, path='/A/a.txt', object_type='file')
        client = ExistingMeiliIndex('http://meili:7700')
        client.call = Mock(side_effect=[dict(hits=[hit]), {'maxTotalHits': 1000}, dict(hits=[hit])])
        client.page(RID, '/A', 'a', 0, 2, acl_filter='(NOT dirs IN ["/A/S"])')
        client.page(RID, '/A', 'a', 2, 2, acl_filter='(NOT dirs IN ["/A/S"])')
        payload = client.call.call_args_list[0].args[2]
        self.assertEqual(payload['filter'],
                         'repo_id = "%s" AND dirs IN ["/A"] AND (NOT dirs IN ["/A/S"])' % RID)
        self.assertEqual(client.call.call_count, 3)
        for bad in ('NOT dirs IN ["/A/S"]', 1):
            with self.assertRaises(SearchUnavailable):
                self.client([hit]).page(RID, '/A', 'a', 0, 2, acl_filter=bad)

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
        saved = indexer.reconcile(repo, None, 0)
        indexer.scan.assert_called_once_with(repo, '/')
        self.assertEqual(saved['tag_cursor'], '')
        indexer.remove.assert_not_called()
        self.assertEqual(saved['head'], 'new')

    def test_move_deletes_old_subtree_and_refreshes_new_path(self):
        client, native = Mock(), Mock()
        repo = SimpleNamespace(id=RID, head_cmmt_id='new')
        native.get_repo.return_value = repo
        native.diff_commits.return_value = [SimpleNamespace(status='mov', name='A', new_name='B')]
        indexer = Indexer(client, native)
        indexer.remove, indexer.refresh = Mock(), Mock()
        indexer.sweep = Mock(return_value='cursor2')
        saved = indexer.reconcile(repo, {'head': 'old', 'tag_cursor': 'cursor1'}, 0)
        indexer.remove.assert_called_once_with(RID, '/A')
        indexer.refresh.assert_called_once_with(repo, '/B')
        indexer.sweep.assert_called_once_with(repo, 'cursor1')
        self.assertEqual(saved['tag_cursor'], 'cursor2')

    def test_changed_head_does_not_acknowledge_checkpoint(self):
        native = Mock()
        native.diff_commits.return_value = []
        native.get_repo.return_value = SimpleNamespace(head_cmmt_id='changed')
        indexer = Indexer(Mock(), native)
        indexer.sweep = Mock(return_value='advanced')
        with self.assertRaises(SearchUnavailable):
            indexer.reconcile(SimpleNamespace(id=RID, head_cmmt_id='new'), {'head': 'old'}, 0)

    def test_tag_sweep_keyset_is_bounded_and_resumable(self):
        repo = SimpleNamespace(id=RID, head_cmmt_id='latest')
        native = Mock()
        native.get_dirent_by_path.return_value = SimpleNamespace(mode=0o100644, size=1, mtime=2)
        indexer = Indexer(Mock(), native)
        indexer.publish = Mock()
        row = ('f' * 32, '/folder', 'a.txt', False)
        fake = ModuleType('seahub.tags.models')
        fake.FileUUIDMap = Mock()
        with patch.dict('sys.modules', {'seahub': ModuleType('seahub'),
                                        'seahub.tags': ModuleType('seahub.tags'),
                                        'seahub.tags.models': fake}), \
                patch('cloudfile_ext.v2.search.worker.tag_labels', return_value={'/folder/a.txt': ['工艺']}) as labels:
            query = fake.FileUUIDMap.objects.filter.return_value
            query.filter.return_value = query
            query.order_by.return_value.values_list.return_value.__getitem__.return_value = [row]
            cursor = indexer.sweep(repo, 'a' * 32)
        self.assertEqual(cursor, 'f' * 32)
        query.filter.assert_called_once_with(uuid__gt='a' * 32)
        self.assertEqual(query.order_by.return_value.values_list.return_value.__getitem__.call_args.args[0].stop, 200)
        labels.assert_called_once_with(RID, [('/folder/a.txt', 'file')])
        self.assertEqual(indexer.publish.call_args.args[0][0]['tags'], ['工艺'])

    def test_empty_tag_sweep_restarts_without_native_calls(self):
        native = Mock()
        indexer = Indexer(Mock(), native)
        fake = ModuleType('seahub.tags.models')
        fake.FileUUIDMap = Mock()
        with patch.dict('sys.modules', {'seahub': ModuleType('seahub'),
                                        'seahub.tags': ModuleType('seahub.tags'),
                                        'seahub.tags.models': fake}):
            query = fake.FileUUIDMap.objects.filter.return_value
            query.filter.return_value = query
            query.order_by.return_value.values_list.return_value.__getitem__.return_value = []
            self.assertEqual(indexer.sweep(SimpleNamespace(id=RID), 'f' * 32), '')
        native.get_dirent_by_path.assert_not_called()

    def test_native_tag_sql_errors_do_not_clear_existing_search_tags(self):
        from cloudfile_ext.v2.search.worker import tag_labels
        fake = ModuleType('cloudfile_ext.v2.tag_reads')
        fake.read = Mock(side_effect=OSError('db unavailable'))
        with patch.dict('sys.modules', {'cloudfile_ext.v2.tag_reads': fake}):
            with self.assertRaises(SearchUnavailable):
                tag_labels(RID, [('/A/a.txt', 'file')])

    def test_document_ids_preserve_existing_format(self):
        self.assertEqual(doc_id(RID, '/members.xlsx'), RID+'-6809ecaf294c5dbd40e64eb8962f86d4470f784b')
