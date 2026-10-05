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


def native_entry(name, directory=True, mtime=10):
    return SimpleNamespace(obj_name=name, mode=stat.S_IFDIR if directory else stat.S_IFREG, mtime=mtime)


def test_default_kinds_still_indexes_directories_only():
    pages = {'/': [native_entry('a.file', False), native_entry('sub'), native_entry('b.file', False)],
             '/sub': []}
    built, written = [], []
    state = dict(pending=[dict(path='/', offset=0)])
    while state['pending']:
        state = advance_page(state,
            read_page=lambda p, o, n: pages[p],
            build_document=lambda p, t, kind: (built.append((p, t, kind)) or dict(path=p)),
            write_documents=lambda rows: written.extend(rows), assert_current=lambda: None)
    assert built == [('/sub', 10, 'dir')]
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
            build_document=lambda p, t, kind: (built.append((p, t, kind)) or dict(path=p, object_type=kind)),
            write_documents=lambda rows: written.extend(rows), assert_current=lambda: None)
        seen_pending.extend(position['path'] for position in state['pending'])
    assert built == [('/doc.txt', 7, 'file'), ('/sub', 10, 'dir'),
                     ('/photo.png', 10, 'file'), ('/sub/inner.txt', 10, 'file')]
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
            build_document=lambda p, t, kind: (built.append((p, t, kind)) or dict(path=p, object_type=kind)),
            write_documents=lambda rows: written.extend(rows), assert_current=lambda: None)
        seen_pending.extend(position['path'] for position in state['pending'])
    # A file-only run still walks through directories to reach nested files; it
    # just builds no directory documents, and still queues only directories.
    assert built == [('/only.txt', 10, 'file'), ('/sub/deep.txt', 10, 'file')]
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
def _configure_command(monkeypatch, entries):
    from cloudfile_ext.management.commands import cf_search_backfill_directories as command
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(head_cmmt_id='a' * 40)
    api.list_dir_by_commit_and_path.side_effect = lambda r, h, p, o, n: entries.get(p, [])
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(command, 'settings', SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch'))
    client = Mock()
    client._call.side_effect = lambda method, path, *args: (
        dict(taskUid=1) if method == 'PUT' else dict(status='succeeded'))
    monkeypatch.setattr(command, 'client_from_settings', lambda: client)
    return command, api


def test_backfill_command_all_kinds_builds_metadata_only_file_documents(monkeypatch, tmp_path):
    command, _ = _configure_command(monkeypatch, {
        '/': [native_entry('sub'), native_entry('report.txt', False, mtime=42)],
        '/sub': []})
    build = Mock(side_effect=lambda r, p, op_user, mtime, max_bytes, object_type:
                 dict(path=p, object_type=object_type))
    monkeypatch.setattr(command, '_build_document', build)
    checkpoint = tmp_path / 'cursor.json'
    out = StringIO()
    command.Command(stdout=out).handle(repo_id='11111111-1111-4111-8111-111111111111',
        checkpoint=str(checkpoint), max_pages=5, kinds='all')
    # path, mtime, max_bytes, object_type: files must never carry bytes or a user.
    assert [(call.args[1], call.args[2], call.args[3], call.args[4], call.args[5])
            for call in build.call_args_list] == [
        ('/sub', '', 10, 0, 'dir'), ('/report.txt', '', 42, 0, 'file')]
    assert json.loads(checkpoint.read_text()) == dict(
        repo_id='11111111-1111-4111-8111-111111111111', head='a' * 40, pending=[],
        pages=2, directories=1, files=1)
    assert out.getvalue().strip() == 'pages=2 directories=1 files=1 complete=True'


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
