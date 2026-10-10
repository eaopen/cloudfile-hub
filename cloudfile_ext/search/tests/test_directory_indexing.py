"""Regression: indexed search must cover folders, including empty ones."""
import stat
import sys
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cloudfile_ext.search import indexer
from cloudfile_ext.search.backfill import advance_page
from cloudfile_ext.search.ops import doc_id


def native_entry(name, directory=True):
    return SimpleNamespace(obj_name=name, mode=stat.S_IFDIR if directory else stat.S_IFREG, mtime=10)


def test_directory_document_never_fetches_file_bytes(monkeypatch):
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(store_id='s', version=1)
    api.get_dir_id_by_path.return_value = 'directory-id'
    api.get_repo_owner.return_value = 'owner'
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    content = Mock(side_effect=AssertionError('directory bytes must never be read'))
    monkeypatch.setattr(indexer, '_fetch_content', content)
    monkeypatch.setattr(indexer, '_fetch_directory_tags', lambda *args: ['folder tag'])
    result = indexer._build_document('repo', '/a/empty.folder', 'user', 10, 1024, 'dir')
    assert result['object_type'] == 'dir'
    assert result['name'] == 'empty.folder' and result['content'] == ''
    assert result['size'] == 0 and result['extension'] == ''
    assert result['dirs'] == ['/a'] and result['tags'] == ['folder tag']
    api.get_file_id_by_path.assert_not_called()
    api.get_file_size.assert_not_called()


def test_directory_tags_use_directory_uuid_and_preserve_names(monkeypatch):
    # Directory tags use the legacy binding table, not the files-only v2 API.
    manager = Mock()
    manager.get_all_file_tag_by_path.return_value.select_related.return_value = [
        SimpleNamespace(tag=SimpleNamespace(name='班组内部文件')),
        SimpleNamespace(tag=SimpleNamespace(name='班组内部文件'))]
    monkeypatch.setitem(sys.modules, 'seahub.tags.models',
                        SimpleNamespace(FileTag=SimpleNamespace(objects=manager)))
    assert indexer._fetch_directory_tags('repo', '/a/folder') == ['班组内部文件']
    manager.get_all_file_tag_by_path.assert_called_once_with('repo', '/a', 'folder', True)
    manager.get_all_file_tag_by_path.side_effect = RuntimeError('database unavailable')
    with pytest.raises(RuntimeError):
        indexer._fetch_directory_tags('repo', '/folder')


def test_directory_activity_create_rename_delete_are_consumed(monkeypatch):
    import django.conf
    monkeypatch.setattr(django.conf, 'settings', SimpleNamespace())
    state = Mock()
    state.get_cursor.return_value = 0
    state.get_pending.return_value = None
    monkeypatch.setitem(sys.modules, 'cloudfile_ext.search.models',
                        SimpleNamespace(SearchIndexState=SimpleNamespace(objects=state)))
    events = [dict(id=1, obj_type='dir', op_type='batch_create', path=None,
                   detail=[dict(path='/empty')], repo_id='repo', op_user='u', timestamp=1),
              dict(id=2, obj_type='folder', op_type='rename', path='/renamed',
                   detail=dict(old_path='/old'), repo_id='repo', op_user='u', timestamp=2),
              dict(id=3, obj_type='dir', op_type='delete', path='/gone',
                   detail={}, repo_id='repo', op_user='u', timestamp=3)]
    monkeypatch.setattr(indexer, '_activities_since', lambda *args: events)
    build = Mock(side_effect=lambda repo, path, *args: dict(id=doc_id(repo, path), object_type='dir'))
    monkeypatch.setattr(indexer, '_build_document', build)
    client = Mock()
    client.upsert_documents.return_value = 11
    client.delete_documents.return_value = 12
    client.task_status.return_value = 'succeeded'
    indexer.index_tick(client=client, max_bytes=0)
    assert {row['id'] for row in client.upsert_documents.call_args.args[0]} == {doc_id('repo', '/empty'), doc_id('repo', '/renamed')}
    assert client.delete_documents.call_args.args[0] == {doc_id('repo', '/old'), doc_id('repo', '/gone')}
    assert [call.args[-1] for call in build.call_args_list] == ['dir', 'folder']
    state.advance.assert_any_call('meilisearch', 3, 'ok')


def test_backfill_indexes_empty_and_nested_directories_without_indexing_file_bytes():
    pages = {'/': [native_entry('empty'), native_entry('nested'), native_entry('file.txt', False)],
             '/empty': [], '/nested': [native_entry('child')], '/nested/child': []}
    reads, written = [], []
    state = dict(pending=[dict(path='/', offset=0)])
    while state['pending']:
        state = advance_page(state,
            read_page=lambda p, o, n: (reads.append((p, o, n)) or pages[p]),
            build_document=lambda p, t, kind, entry: dict(path=p), write_documents=lambda rows: written.extend(rows), assert_current=lambda: None)
    assert [row['path'] for row in written] == ['/empty', '/nested', '/nested/child']
    assert state['pages'] == 4 and state['directories'] == 3
    assert all(limit == 101 for _, _, limit in reads)


def test_backfill_failed_write_and_snapshot_change_do_not_advance_original_checkpoint():
    state = dict(pending=[dict(path='/', offset=0)])
    for fail in ('write', 'snapshot'):
        def assert_current():
            if fail == 'snapshot':
                raise ValueError('changed')
        def write(rows):
            raise ValueError('write failed')
        with pytest.raises(ValueError):
            advance_page(state, read_page=lambda *args: [native_entry('folder')],
                build_document=lambda p, t, kind, entry: dict(path=p), write_documents=write, assert_current=assert_current)
        assert state == dict(pending=[dict(path='/', offset=0)])


def test_backfill_continues_wide_directory_without_skipping_next_page():
    state = dict(pending=[dict(path='/', offset=0)])
    state = advance_page(state, read_page=lambda *args: [native_entry(str(i), False) for i in range(101)],
        build_document=lambda *args: pytest.fail('files must not be indexed'),
        write_documents=lambda *args: pytest.fail('no directories to write'), assert_current=lambda: None)
    assert state['pending'] == [dict(path='/', offset=100)]

# Exercise the real operator command too: progress is durable only after the
# asynchronous Meili task succeeds, and a second invocation resumes the stack.
def test_backfill_command_resumes_and_waits_for_index_task(monkeypatch, tmp_path):
    import json
    from cloudfile_ext.management.commands import cf_search_backfill_directories as command
    repo_id = '11111111-1111-4111-8111-111111111111'
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(head_cmmt_id='a' * 40)
    api.list_dir_by_commit_and_path.side_effect = lambda r, h, p, o, n: [native_entry('empty')] if p == '/' else []
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(command, 'settings', SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch'))
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    client = Mock()
    client._call.side_effect = lambda method, path, *args: dict(taskUid=1) if method == 'PUT' else dict(status='succeeded')
    monkeypatch.setattr(command, 'client_from_settings', lambda: client)
    checkpoint = tmp_path / 'cursor.json'
    options = dict(repo_id=repo_id, checkpoint=str(checkpoint), max_pages=1)
    command.Command().handle(**options)
    saved = json.loads(checkpoint.read_text())
    assert saved['pending'] == [dict(path='/empty', offset=0)]
    assert saved['directories'] == 1
    client._call.assert_any_call('GET', '/tasks/1')
    command.Command().handle(**options)
    assert json.loads(checkpoint.read_text())['pending'] == []
    assert [call.args[2] for call in api.list_dir_by_commit_and_path.call_args_list] == ['/', '/empty']


def test_backfill_command_directory_writes_are_batched_not_per_page(monkeypatch, tmp_path):
    import json
    from cloudfile_ext.management.commands import cf_search_backfill_directories as command
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(head_cmmt_id='a' * 40)
    pages = {'/': [native_entry('a'), native_entry('b')], '/a': [], '/b': []}
    api.list_dir_by_commit_and_path.side_effect = lambda r, h, p, o, n: pages.get(p, [])
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(command, 'settings', SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch'))
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    writes = []
    client = Mock()

    def call(method, path, *args):
        if method == 'PUT':
            writes.append([row['path'] for row in args[0]])
            return dict(taskUid=1)
        return dict(status='succeeded')

    client._call.side_effect = call
    monkeypatch.setattr(command, 'client_from_settings', lambda: client)
    checkpoint = tmp_path / 'cursor.json'
    out = StringIO()
    command.Command(stdout=out).handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=10, flush_docs=500)
    # Three directory pages, two documents, one Meili write instead of three.
    assert writes == [['/a', '/b']]
    assert out.getvalue().strip() == 'pages=3 directories=2 files=0 complete=True'
    assert json.loads(checkpoint.read_text()) == dict(
        repo_id='11111111-1111-4111-8111-111111111111', head='a' * 40, pending=[],
        pages=3, directories=2, files=0)


def test_backfill_command_does_not_checkpoint_a_failed_async_write(monkeypatch, tmp_path):
    from django.core.management.base import CommandError
    from cloudfile_ext.management.commands import cf_search_backfill_directories as command
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(head_cmmt_id='a' * 40)
    api.list_dir_by_commit_and_path.return_value = [native_entry('empty')]
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(command, 'settings', SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch'))
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    client = Mock()
    client._call.side_effect = [dict(taskUid=1), dict(status='failed')]
    monkeypatch.setattr(command, 'client_from_settings', lambda: client)
    checkpoint = tmp_path / 'cursor.json'
    with pytest.raises(CommandError, match='not advanced'):
        command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111', checkpoint=str(checkpoint), max_pages=1)
    assert not checkpoint.exists()
