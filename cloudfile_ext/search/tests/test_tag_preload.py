"""Regression: the backfill resolves tags once per run, not once per file.

The per-path lookups (`_fetch_tags` / `_fetch_directory_tags`) turned a full
library walk into two queries plus a repo RPC for every document -- measured at
~26 ms a call, which capped the backfill near 20 files/s. The preloaded maps
must answer exactly what the per-path lookups would, and the incremental
indexer (`tags=None`) must keep its old behaviour untouched.

The ORM equivalence runs in a subprocess with an isolated SQLite schema, the
same pattern as cloudfile_ext/legacy_tags/tests/test_orm.py, so the real
managers are exercised without the shared pytest session's database.
"""
import sys
from io import StringIO
from pathlib import Path
from subprocess import run
from types import SimpleNamespace
from unittest.mock import Mock

from cloudfile_ext.search.tests.test_search_file_backfill import native_entry


def _command_harness(monkeypatch, entries):
    from cloudfile_ext.management.commands import cf_search_backfill_directories as command
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(
        head_cmmt_id='a' * 40, store_id='store', version=1)
    api.list_dir_by_commit_and_path.side_effect = lambda r, h, p, o, n: entries.get(p, [])
    api.get_dir_id_by_path.return_value = 'dir-id'
    api.get_file_id_by_path.return_value = 'file-id'
    api.get_file_size.return_value = 0
    api.get_repo_owner.return_value = 'owner'
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(command, 'settings', SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch'))
    client = Mock()
    monkeypatch.setattr(command, 'client_from_settings', lambda: client)
    return command, api, client, '11111111-1111-4111-8111-111111111111'


def test_backfill_command_uses_preloaded_tags_and_never_looks_up_per_path(monkeypatch, tmp_path):
    from cloudfile_ext.management.commands import cf_search_backfill_directories as command
    from cloudfile_ext.search import indexer
    entries = {'/': [native_entry('sub'), native_entry('tagged.txt', False)],
               '/sub': [native_entry('inner.txt', False)]}
    command_module, _, client, repo_id = _command_harness(monkeypatch, entries)
    writes = []

    def call(method, path, *args):
        if method == 'PUT':
            writes.append(list(args[0]))
            return dict(taskUid=1)
        return dict(status='succeeded')

    client._call.side_effect = call
    monkeypatch.setattr(command_module, 'preload_tags',
                        lambda repo: ({'/tagged.txt': ['file-tag'], '/sub/inner.txt': []},
                                      {'/sub': ['dir-tag']}))
    monkeypatch.setattr(indexer, '_fetch_content', lambda *args: '')
    # The real _build_document runs; a per-path lookup would raise here.
    file_lookup = Mock(side_effect=AssertionError('per-path file tag lookup'))
    dir_lookup = Mock(side_effect=AssertionError('per-path directory tag lookup'))
    monkeypatch.setattr(indexer, '_fetch_tags', file_lookup)
    monkeypatch.setattr(indexer, '_fetch_directory_tags', dir_lookup)

    out = StringIO()
    command_module.Command(stdout=out).handle(
        repo_id=repo_id, checkpoint=str(tmp_path / 'cursor.json'), max_pages=5, kinds='all')

    assert {row['path']: row['tags'] for row in writes[0]} == {
        '/sub': ['dir-tag'], '/tagged.txt': ['file-tag'], '/sub/inner.txt': []}
    assert out.getvalue().strip() == 'pages=2 directories=1 files=2 complete=True'
    file_lookup.assert_not_called()
    dir_lookup.assert_not_called()


def test_build_document_without_a_snapshot_keeps_per_path_lookups(monkeypatch):
    from cloudfile_ext.search import indexer
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(store_id='store', version=1)
    api.get_file_id_by_path.return_value = 'file-id'
    api.get_dir_id_by_path.return_value = 'dir-id'
    api.get_file_size.return_value = 0
    api.get_repo_owner.return_value = 'owner'
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(indexer, '_fetch_content', lambda *args: '')
    file_lookup = Mock(return_value=['file-tag'])
    dir_lookup = Mock(return_value=['dir-tag'])
    monkeypatch.setattr(indexer, '_fetch_tags', file_lookup)
    monkeypatch.setattr(indexer, '_fetch_directory_tags', dir_lookup)

    assert indexer._build_document('repo', '/a/f.txt', 'user', 10, 0, 'file')['tags'] == ['file-tag']
    assert file_lookup.call_args.args == ('repo', '/a/f.txt')
    assert indexer._build_document('repo', '/a', 'user', 10, 0, 'dir')['tags'] == ['dir-tag']
    assert dir_lookup.call_args.args == ('repo', '/a')

    # An explicit snapshot -- including an empty one -- is authoritative and
    # never falls back to a lookup.
    file_lookup.reset_mock()
    dir_lookup.reset_mock()
    assert indexer._build_document('repo', '/a/f.txt', 'user', 10, 0, 'file', tags=[])['tags'] == []
    assert indexer._build_document('repo', '/a/x', 'user', 10, 0, 'dir',
                                   tags=['snapshot'])['tags'] == ['snapshot']
    file_lookup.assert_not_called()
    dir_lookup.assert_not_called()


def test_preloaded_maps_match_per_path_lookups_in_isolated_orm():
    result = run([sys.executable, str(Path(__file__).with_name('preload_check.py'))],
                 text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
