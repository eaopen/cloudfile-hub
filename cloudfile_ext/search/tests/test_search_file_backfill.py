"""Regression: the legacy index file backfill stays bounded and metadata-only.

The legacy index (`cloudfile_files`) is fed by seafevents' Activity stream only,
so it covers a fraction of a library's files. This repair walks each library once
from a pinned commit. Files are leaves: their documents are built from the native
directory entry with max_bytes=0, so no page ever risks the Meili payload limit.
"""
import json
import stat
import sys
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cloudfile_ext.search.backfill import advance_page


def native_entry(name, directory=True, mtime=10, size=None):
    # `size` is only set by tests that drive the entry-based fast path; leaving
    # it None keeps a fixture entry looking like one the fast path must reject
    # (a file without an integral size), which exercises the RPC fallback.
    return SimpleNamespace(obj_name=name, mode=stat.S_IFDIR if directory else stat.S_IFREG,
                           mtime=mtime, size=size)


def test_default_kinds_still_indexes_directories_only():
    pages = {'/': [native_entry('a.file', False), native_entry('sub'), native_entry('b.file', False)],
             '/sub': []}
    built, written = [], []
    state = dict(pending=[dict(path='/', offset=0)])
    while state['pending']:
        state = advance_page(state,
            read_page=lambda p, o, n: pages[p],
            build_document=lambda p, t, kind, entry: (built.append((p, t, kind, entry)) or dict(path=p)),
            write_documents=lambda rows: written.extend(rows), assert_current=lambda: None)
    assert built == [('/sub', 10, 'dir', pages['/'][1])]
    assert [row['path'] for row in written] == ['/sub']
    assert state['directories'] == 1 and state['files'] == 0


def test_all_kinds_index_files_with_object_type_and_never_descend_them():
    pages = {'/': [native_entry('doc.txt', False, mtime=7), native_entry('sub'),
                   native_entry('photo.png', False)],
             '/sub': [native_entry('inner.txt', False)]}
    built, written, seen_pending = [], [], []
    state = dict(pending=[dict(path='/', offset=0)])
    while state['pending']:
        state = advance_page(state, kinds=('dir', 'file'),
            read_page=lambda p, o, n: pages[p],
            build_document=lambda p, t, kind, entry: (built.append((p, t, kind, entry)) or dict(path=p, object_type=kind)),
            write_documents=lambda rows: written.extend(rows), assert_current=lambda: None)
        seen_pending.extend(position['path'] for position in state['pending'])
    # The callback receives the exact native entry the page was validated from.
    assert built == [('/doc.txt', 7, 'file', pages['/'][0]),
                     ('/sub', 10, 'dir', pages['/'][1]),
                     ('/photo.png', 10, 'file', pages['/'][2]),
                     ('/sub/inner.txt', 10, 'file', pages['/sub'][0])]
    assert [row['object_type'] for row in written] == ['file', 'dir', 'file', 'file']
    # Only directories are ever queued for descent, so a file-heavy tree cannot
    # grow the continuation stack beyond what directories justify.
    assert set(seen_pending) == {'/sub'}
    assert state['directories'] == 1 and state['files'] == 3


def test_file_kinds_walks_directories_for_nested_files_without_dir_documents():
    pages = {'/': [native_entry('sub'), native_entry('only.txt', False)],
             '/sub': [native_entry('deep.txt', False)]}
    built, written, seen_pending = [], [], []
    state = dict(pending=[dict(path='/', offset=0)])
    while state['pending']:
        state = advance_page(state, kinds=('file',),
            read_page=lambda p, o, n: pages[p],
            build_document=lambda p, t, kind, entry: (built.append((p, t, kind, entry)) or dict(path=p, object_type=kind)),
            write_documents=lambda rows: written.extend(rows), assert_current=lambda: None)
        seen_pending.extend(position['path'] for position in state['pending'])
    # A file-only run still walks through directories to reach nested files; it
    # just builds no directory documents, and still queues only directories.
    assert built == [('/only.txt', 10, 'file', pages['/'][1]),
                     ('/sub/deep.txt', 10, 'file', pages['/sub'][0])]
    assert [row['object_type'] for row in written] == ['file', 'file']
    assert set(seen_pending) == {'/sub'}
    assert state['directories'] == 0 and state['files'] == 2 and state['pending'] == []


def test_missing_file_document_aborts_page_before_write():
    state = dict(pending=[dict(path='/', offset=0)])
    with pytest.raises(ValueError, match='file changed'):
        advance_page(state, kinds=('dir', 'file'),
            read_page=lambda *args: [native_entry('gone.txt', False)],
            build_document=lambda *args: None,
            write_documents=lambda *args: pytest.fail('nothing may be written'),
            assert_current=lambda: None)
    assert state == dict(pending=[dict(path='/', offset=0)])


def test_unknown_kind_is_rejected():
    with pytest.raises(ValueError, match='kinds'):
        advance_page(dict(pending=[dict(path='/', offset=0)]), kinds=('link',),
            read_page=lambda *args: pytest.fail('nothing may be read'),
            build_document=lambda *args: pytest.fail('nothing may be built'),
            write_documents=lambda *args: pytest.fail('nothing may be written'),
            assert_current=lambda: None)


# Exercise the real operator command: --kinds all must build file documents
# without fetching bytes, report the files counter, and refuse a checkpoint that
# lost or corrupted that counter.
def _configure_command(monkeypatch, entries, on_write=None, write_status='succeeded'):
    from cloudfile_ext.management.commands import cf_search_backfill_directories as command
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(head_cmmt_id='a' * 40)
    api.list_dir_by_commit_and_path.side_effect = lambda r, h, p, o, n: entries.get(p, [])
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(command, 'settings', SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch'))
    client = Mock()

    def call(method, path, *args):
        if method == 'PUT':
            if on_write is not None:
                on_write(list(args[0]))
            return dict(taskUid=1)
        return dict(status=write_status)

    client._call.side_effect = call
    monkeypatch.setattr(command, 'client_from_settings', lambda: client)
    return command, api


def test_backfill_command_all_kinds_builds_metadata_only_file_documents(monkeypatch, tmp_path):
    writes = []
    command, api = _configure_command(monkeypatch, {
        '/': [native_entry('sub'), native_entry('report.txt', False, mtime=42)],
        '/sub': []}, on_write=lambda documents: writes.append(documents))
    api.get_repo_owner.return_value = 'owner'
    # Pin the tag snapshot so the directory entry reaches the fast builder
    # instead of the preload-failure fallback (which the test DB blocks anyway).
    monkeypatch.setattr(command, 'preload_tags', lambda repo: ({}, {}))
    build = Mock(side_effect=lambda r, p, op_user, mtime, max_bytes, object_type, **kwargs:
                 dict(path=p, object_type=object_type))
    monkeypatch.setattr(command, '_build_document', build)
    checkpoint = tmp_path / 'cursor.json'
    out = StringIO()
    command.Command(stdout=out).handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=5, kinds='all')
    # The directory came from the entry-based fast builder (a mock document
    # would carry no name), while this file's entry has no usable size, so it
    # must fall back to the RPC builder: path, op_user, mtime, max_bytes, kind.
    assert [row['path'] for row in writes[0]] == ['/sub', '/report.txt']
    assert writes[0][0]['name'] == 'sub' and writes[0][0]['content'] == ''
    assert [(call.args[1], call.args[2], call.args[3], call.args[4], call.args[5])
            for call in build.call_args_list] == [
        ('/report.txt', '', 42, 0, 'file')]
    assert json.loads(checkpoint.read_text()) == dict(
        repo_id='11111111-1111-4111-8111-111111111111', head='a' * 40, pending=[],
        pages=2, directories=1, files=1)
    assert out.getvalue().strip() == 'pages=2 directories=1 files=1 complete=True'


def test_backfill_command_builds_documents_from_native_entries_without_per_file_rpc(monkeypatch, tmp_path):
    # 50 file entries in one page: every document must come from entry.size /
    # entry.mtime, so the four per-document native calls disappear entirely.
    entries = {'/': [native_entry('f%02d.txt' % i, False, mtime=1000 + i, size=i * 7)
                     for i in range(50)]}
    writes = []
    command, api = _configure_command(monkeypatch, entries,
                                      on_write=lambda documents: writes.append(documents))
    api.get_repo_owner.return_value = 'owner'
    # Deterministic fast path: an empty snapshot is enough, no per-path lookups.
    monkeypatch.setattr(command, 'preload_tags', lambda repo: ({}, {}))
    out = StringIO()
    command.Command(stdout=out).handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(tmp_path / 'cursor.json'), max_pages=5, kinds='all')
    documents = {row['path']: row for row in writes[0]}
    assert len(documents) == 50
    assert documents['/f00.txt']['size'] == 0
    assert documents['/f07.txt']['size'] == 49
    assert documents['/f07.txt']['mtime'] == 1007
    assert documents['/f07.txt']['creator'] == 'owner'
    assert all(row['content'] == '' for row in documents.values())
    # No per-file RPC at all. get_repo is only the head pin (once) plus the
    # per-page re-checks, so it stays bounded by pages, not by file count.
    api.get_file_id_by_path.assert_not_called()
    api.get_dir_id_by_path.assert_not_called()
    api.get_file_size.assert_not_called()
    assert api.get_repo.call_count <= 10
    assert out.getvalue().strip() == 'pages=1 directories=0 files=50 complete=True'


def test_backfill_command_falls_back_when_entry_lacks_a_usable_size(monkeypatch, tmp_path):
    command, api = _configure_command(monkeypatch, {
        '/': [native_entry('report.txt', False, mtime=42, size=None)]})
    api.get_repo_owner.return_value = 'owner'
    fast = Mock(side_effect=AssertionError('fast path must not run on a sizeless entry'))
    slow = Mock(return_value=dict(id='x', path='/report.txt', object_type='file', size=99))
    monkeypatch.setattr(command, 'build_backfill_document', fast)
    monkeypatch.setattr(command, '_build_document', slow)
    checkpoint = tmp_path / 'cursor.json'
    command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=5, kinds='all')
    fast.assert_not_called()
    slow.assert_called_once()
    # The RPC builder is handed the pinned snapshot's mtime and max_bytes=0, and
    # the fallback document is still what gets checkpointed as durable.
    assert slow.call_args.args == ('11111111-1111-4111-8111-111111111111',
                                   '/report.txt', '', 42, 0, 'file')
    assert json.loads(checkpoint.read_text())['files'] == 1


def test_backfill_entry_is_usable_rejects_missing_and_non_integral_sizes():
    from cloudfile_ext.search.indexer import backfill_entry_is_usable
    assert backfill_entry_is_usable(native_entry('f.txt', False, size=0), 'file') is True
    assert backfill_entry_is_usable(native_entry('f.txt', False, size=123), 'file') is True
    assert backfill_entry_is_usable(native_entry('f.txt', False, size=None), 'file') is False
    assert backfill_entry_is_usable(native_entry('f.txt', False, size=-1), 'file') is False
    assert backfill_entry_is_usable(native_entry('f.txt', False, size='12'), 'file') is False
    assert backfill_entry_is_usable(SimpleNamespace(), 'file') is False
    assert backfill_entry_is_usable(None, 'file') is False
    # Directories read no size, so an entry with nothing but mtime is enough.
    assert backfill_entry_is_usable(SimpleNamespace(mtime=1), 'dir') is True
    assert backfill_entry_is_usable(None, 'dir') is False


def test_backfill_fast_builder_matches_the_rpc_builder_for_files_and_directories(monkeypatch):
    from cloudfile_ext.search import indexer
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(store_id='store', version=1)
    api.get_file_id_by_path.return_value = 'file-id'
    api.get_dir_id_by_path.return_value = 'dir-id'
    api.get_file_size.return_value = 4321
    api.get_repo_owner.return_value = 'owner'
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(indexer, '_fetch_content', lambda *args: '')

    for entry, object_type, path, tags in [
            (native_entry('report.txt', False, mtime=42, size=4321), 'file',
             '/a/report.txt', ['file-tag']),
            (native_entry('folder', True, mtime=42), 'dir', '/a/folder', ['dir-tag'])]:
        slow = indexer._build_document(
            'repo', path, '', entry.mtime, 0, object_type, tags=tags)
        api.reset_mock()
        fast = indexer.build_backfill_document(
            'repo', path, entry, object_type, tags, 'owner')
        assert fast == slow, (path, fast, slow)
        assert list(fast) == list(slow)
        # The fast builder itself performs no native RPC.
        api.get_file_id_by_path.assert_not_called()
        api.get_dir_id_by_path.assert_not_called()
        api.get_file_size.assert_not_called()
        api.get_repo.assert_not_called()
        api.get_repo_owner.assert_not_called()


def test_backfill_command_rejects_checkpoint_without_valid_files_counter(monkeypatch, tmp_path):
    from django.core.management.base import CommandError
    command, _ = _configure_command(monkeypatch, {'/': []})
    base = dict(repo_id='11111111-1111-4111-8111-111111111111', head='a' * 40,
                pending=[dict(path='/', offset=0)], pages=0, directories=0)
    for index, state in enumerate([base, dict(base, files=-1), dict(base, files='0'), dict(base, files=None)]):
        checkpoint = tmp_path / ('cursor-%d.json' % index)
        checkpoint.write_text(json.dumps(state))
        with pytest.raises(CommandError, match='Checkpoint is invalid'):
            command.Command().handle(repo_id=state['repo_id'], checkpoint=str(checkpoint),
                                     max_pages=1, kinds='all')


def test_backfill_command_does_not_checkpoint_a_pending_async_write(monkeypatch, tmp_path):
    from django.core.management.base import CommandError
    command, _ = _configure_command(monkeypatch, {'/': [native_entry('report.txt', False)]})
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    command.client_from_settings()._call.side_effect = lambda method, path, *args: (
        dict(taskUid=1) if method == 'PUT' else dict(status='enqueued'))
    # A task stuck enqueued must time out, not park the operator forever.
    ticks = iter([0.0, 0.0, 31.0])
    monkeypatch.setattr(command, 'time', SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda seconds: None))
    checkpoint = tmp_path / 'cursor.json'
    with pytest.raises(CommandError, match='pending'):
        command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111',
            checkpoint=str(checkpoint), max_pages=1, kinds='all')
    assert not checkpoint.exists()


# Batching: a directory-heavy library fills one Meili payload from many small
# native pages. The buffer bounds memory; the checkpoint may only describe
# documents that are already durable in Meilisearch.
def _chain_entries(count):
    """`count` native pages holding one nested directory document each."""
    pages = {}
    path = '/'
    for index in range(count):
        if index + 1 == count:
            pages[path] = []
            continue
        name = 'd%d' % (index + 1)
        pages[path] = [native_entry(name)]
        path = ('' if path == '/' else path) + '/' + name
    return pages


def test_backfill_command_batches_small_pages_into_one_write(monkeypatch, tmp_path):
    checkpoint = tmp_path / 'cursor.json'
    writes, checkpoint_at_write = [], []

    def on_write(documents):
        writes.append([row['path'] for row in documents])
        checkpoint_at_write.append(checkpoint.read_text() if checkpoint.exists() else None)

    command, _ = _configure_command(monkeypatch, {
        '/': [native_entry('a'), native_entry('b')],
        '/a': [native_entry('x.txt', False)],
        '/b': [native_entry('y.txt', False)]}, on_write=on_write)
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    out = StringIO()
    command.Command(stdout=out).handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=10, kinds='all', flush_docs=5)
    # Three small pages, four documents, exactly one Meili write.
    assert writes == [['/a', '/b', '/a/x.txt', '/b/y.txt']]
    # Those documents were still buffered when the run ran out of pages, so the
    # leftover flush had to happen before any checkpoint existed.
    assert checkpoint_at_write == [None]
    assert json.loads(checkpoint.read_text()) == dict(
        repo_id='11111111-1111-4111-8111-111111111111', head='a' * 40, pending=[],
        pages=3, directories=2, files=2)
    assert out.getvalue().strip() == 'pages=3 directories=2 files=2 complete=True'


def test_backfill_command_flushes_at_threshold_and_checkpoints_only_after(monkeypatch, tmp_path):
    checkpoint = tmp_path / 'cursor.json'
    writes, checkpoint_at_write = [], []

    def on_write(documents):
        writes.append([row['path'] for row in documents])
        checkpoint_at_write.append(checkpoint.read_text() if checkpoint.exists() else None)

    command, _ = _configure_command(monkeypatch, _chain_entries(5), on_write=on_write)
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=10, kinds='dir', flush_docs=2)
    # One document per page: two pages fill the threshold, so four documents go
    # out as two writes of two instead of four writes of one.
    assert writes == [['/d1', '/d1/d2'], ['/d1/d2/d3', '/d1/d2/d3/d4']]
    assert checkpoint_at_write[0] is None
    # The second write can only see the checkpoint of the first successful flush
    # (pages 1-2), never pages 3-4 whose documents are still in the buffer.
    assert json.loads(checkpoint_at_write[1])['pages'] == 2
    assert json.loads(checkpoint.read_text())['pages'] == 5


def test_backfill_command_flushes_leftovers_before_final_checkpoint(monkeypatch, tmp_path):
    checkpoint = tmp_path / 'cursor.json'
    seeded = dict(repo_id='11111111-1111-4111-8111-111111111111', head='a' * 40,
                  pending=[dict(path='/d1', offset=0)], pages=1, directories=1, files=0)
    checkpoint.write_text(json.dumps(seeded))
    snapped = []

    def on_write(documents):
        snapped.append(([row['path'] for row in documents], checkpoint.read_text()))

    command, _ = _configure_command(monkeypatch, _chain_entries(5), on_write=on_write)
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    command.Command().handle(repo_id=seeded['repo_id'], checkpoint=str(checkpoint),
                             max_pages=10, kinds='dir', flush_docs=2)
    assert [paths for paths, _ in snapped] == [['/d1/d2', '/d1/d2/d3'], ['/d1/d2/d3/d4']]
    # The first batch is written while the on-disk checkpoint is still the one
    # this run resumed from.
    assert snapped[0][1] == json.dumps(seeded)
    # The trailing document is flushed before the final checkpoint claims it.
    assert json.loads(snapped[1][1])['pages'] == 3
    assert json.loads(checkpoint.read_text()) == dict(
        repo_id=seeded['repo_id'], head='a' * 40, pending=[], pages=5, directories=4, files=0)


@pytest.mark.parametrize('status, message', [('failed', 'not advanced'), ('enqueued', 'pending')])
def test_backfill_command_failed_flush_keeps_previous_checkpoint(monkeypatch, tmp_path, status, message):
    from django.core.management.base import CommandError
    command, _ = _configure_command(monkeypatch, _chain_entries(5))
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    checkpoint = tmp_path / 'cursor.json'
    # One durable page first: the next run must not move this file on failure.
    command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=1, kinds='dir', flush_docs=2)
    before = checkpoint.read_text()
    assert json.loads(before)['pages'] == 1
    command.client_from_settings()._call.side_effect = lambda method, path, *args: (
        dict(taskUid=1) if method == 'PUT' else dict(status=status))
    if status == 'enqueued':
        ticks = iter([0.0, 0.0, 31.0])
        monkeypatch.setattr(command, 'time', SimpleNamespace(
            monotonic=lambda: next(ticks), sleep=lambda seconds: None))
    with pytest.raises(CommandError, match=message):
        command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111',
            checkpoint=str(checkpoint), max_pages=10, kinds='dir', flush_docs=1)
    assert checkpoint.read_text() == before


def test_backfill_command_exits_non_zero_on_failed_flush(monkeypatch, tmp_path):
    command, _ = _configure_command(monkeypatch, _chain_entries(5))
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    checkpoint = tmp_path / 'cursor.json'
    command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=1, kinds='dir', flush_docs=2)
    before = checkpoint.read_text()
    command.client_from_settings()._call.side_effect = lambda method, path, *args: (
        dict(taskUid=1) if method == 'PUT' else dict(status='failed'))
    # The operator-facing entry point must report the failure as a non-zero exit.
    with pytest.raises(SystemExit) as exit_info:
        command.Command().run_from_argv(['manage.py', 'cf_search_backfill_directories',
            '--skip-checks', '--repo-id', '11111111-1111-4111-8111-111111111111',
            '--checkpoint', str(checkpoint), '--max-pages', '10', '--kinds', 'dir',
            '--flush-docs', '1'])
    assert exit_info.value.code != 0
    assert checkpoint.read_text() == before


@pytest.mark.parametrize('flush_docs', [0, -1, 2001, 10 ** 9, None, '500'])
def test_backfill_command_rejects_out_of_range_flush_docs(monkeypatch, tmp_path, flush_docs):
    from django.core.management.base import CommandError
    command, api = _configure_command(monkeypatch, {'/': []})
    checkpoint = tmp_path / 'cursor.json'
    with pytest.raises(CommandError, match='flush-docs'):
        command.Command().handle(repo_id='11111111-1111-4111-8111-111111111111',
            checkpoint=str(checkpoint), max_pages=1, kinds='dir', flush_docs=flush_docs)
    assert not checkpoint.exists()
    # Rejected before the library or the index is touched.
    assert api.get_repo.call_count == 0


@pytest.mark.parametrize('flush_docs', [1, 2000])
def test_backfill_command_accepts_flush_docs_bounds(monkeypatch, tmp_path, flush_docs):
    command, _ = _configure_command(monkeypatch, {'/': [native_entry('empty')], '/empty': []})
    monkeypatch.setattr(command, '_build_document', lambda r, p, *args: dict(path=p))
    out = StringIO()
    command.Command(stdout=out).handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(tmp_path / 'cursor.json'), max_pages=5, kinds='dir', flush_docs=flush_docs)
    assert out.getvalue().strip() == 'pages=2 directories=1 files=0 complete=True'
