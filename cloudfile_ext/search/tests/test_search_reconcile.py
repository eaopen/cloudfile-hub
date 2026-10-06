"""Regression: the legacy-index completeness gate is bounded, batched and read-only.

`cf_search_reconcile` walks one library with the same head-pinned bounded pattern
as the backfill command and asks the legacy `cloudfile_files` index whether every
visited native entry has a document. These tests drive the real command with a
stubbed index client: the walk, the counters, the batch route, the checkpoint
semantics and the exit codes are all exercised, while no Meilisearch is reached.
"""
import fcntl
import json
import stat
import sys
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloudfile_ext.search.ops import doc_id

REPO = '11111111-1111-4111-8111-111111111111'
HEAD = 'a' * 40


def native_entry(name, directory=True, mtime=10, size=None):
    return SimpleNamespace(obj_name=name, mode=stat.S_IFDIR if directory else stat.S_IFREG,
                           mtime=mtime, size=size)


class FakeIndex(object):
    """Index stub recording which route answered each existence question."""

    def __init__(self, existing_ids=(), repo_documents=(), partial_ids=()):
        self.existing = set(existing_ids)
        self.repo_documents = list(repo_documents)
        #: ids that exist but which the batch route withholds from `results`
        #: while still counting them in `total` -- a truncated page.
        self.partial = set(partial_ids)
        self.fetch_calls = []
        self.get_calls = []
        self.repo_calls = []

    def fetch_documents(self, ids, limit=None):
        ids = list(ids)
        self.fetch_calls.append((ids, limit))
        matched = [i for i in ids if i in self.existing]
        results = [{'id': i} for i in matched if i not in self.partial]
        return {'results': results, 'offset': 0, 'limit': limit or 20,
                'total': len(matched)}

    def document_exists(self, document_id):
        self.get_calls.append(document_id)
        return document_id in self.existing

    def documents_for_repo(self, repo_id, offset, limit):
        self.repo_calls.append((repo_id, offset, limit))
        return {'results': self.repo_documents[offset:offset + limit],
                'offset': offset, 'limit': limit, 'total': len(self.repo_documents)}


class NoBatchIndex(FakeIndex):
    """A deployment whose /documents/fetch route is absent or unusable."""

    def fetch_documents(self, ids, limit=None):
        raise RuntimeError('route not available')


def _configure(monkeypatch, entries, index, head=HEAD):
    from cloudfile_ext.management.commands import cf_search_reconcile as command
    api = Mock()
    api.get_repo.return_value = SimpleNamespace(head_cmmt_id=head)
    api.list_dir_by_commit_and_path.side_effect = lambda r, h, p, o, n: entries.get(p, [])
    api.get_repo_owner.return_value = 'owner'
    monkeypatch.setitem(sys.modules, 'seaserv', SimpleNamespace(seafile_api=api))
    monkeypatch.setattr(command, 'settings', SimpleNamespace(CF_PROVIDER_SEARCH='meilisearch'))
    monkeypatch.setattr(command, 'client_from_settings', lambda: index)
    return command, api


def _run(command, out, **options):
    options.setdefault('repo_id', REPO)
    options.setdefault('max_pages', 10)
    out = out or StringIO()
    command.Command(stdout=out).handle(**options)
    return json.loads(out.getvalue())


def test_reconcile_reports_native_indexed_and_missing_counts(monkeypatch, tmp_path):
    entries = {'/': [native_entry('sub'), native_entry('a.txt', False)],
               '/sub': [native_entry('b.txt', False)]}
    index = FakeIndex(existing_ids={doc_id(REPO, '/sub'), doc_id(REPO, '/a.txt')})
    command, _ = _configure(monkeypatch, entries, index)
    report = _run(command, StringIO(), checkpoint=str(tmp_path / 'c.json'), threshold=0.0)
    assert report['repo_id'] == REPO and report['head'] == HEAD
    assert report['native_files'] == 2 and report['native_dirs'] == 1
    assert report['indexed_files'] == 1 and report['indexed_dirs'] == 1
    assert report['missing_files'] == 1 and report['missing_dirs'] == 0
    assert report['coverage_ratio'] == 0.5
    assert report['pages'] == 2 and report['complete'] is True
    assert report['sample_missing'] == [{'path': '/sub/b.txt', 'object_type': 'file'}]


def test_reconcile_uses_one_batch_fetch_per_page_and_no_per_document_call(monkeypatch, tmp_path):
    entries = {'/': [native_entry('sub'), native_entry('a.txt', False)],
               '/sub': [native_entry('b.txt', False)]}
    index = FakeIndex(existing_ids={doc_id(REPO, p)
                                    for p in ('/sub', '/a.txt', '/sub/b.txt')})
    command, _ = _configure(monkeypatch, entries, index)
    _run(command, StringIO(), checkpoint=str(tmp_path / 'c.json'), threshold=0.0)
    batches = [ids for ids, _ in index.fetch_calls if ids]
    # Two visited pages, one batch each, plus the empty-id probe call.
    assert [len(batch) for batch in batches] == [2, 1]
    assert [ids for ids, _ in index.fetch_calls if not ids] == [[]]
    # Every batch asked for exactly the page's document ids.
    assert {doc_id(REPO, '/sub'), doc_id(REPO, '/a.txt')} == set(batches[0])
    assert index.get_calls == []


def test_reconcile_resolves_a_truncated_batch_by_id_instead_of_misreporting(monkeypatch, tmp_path):
    hidden = doc_id(REPO, '/a.txt')
    entries = {'/': [native_entry('sub'), native_entry('a.txt', False)], '/sub': []}
    index = FakeIndex(existing_ids={doc_id(REPO, '/sub'), hidden}, partial_ids={hidden})
    command, _ = _configure(monkeypatch, entries, index)
    report = _run(command, StringIO(), checkpoint=str(tmp_path / 'c.json'), threshold=0.0)
    # Only the withheld id needed the per-document fallback; the rest came back
    # in the batch, so the missing count stays honest.
    assert index.get_calls == [hidden]
    assert report['indexed_files'] == 1 and report['missing_files'] == 0


def test_reconcile_falls_back_to_per_document_get_when_batch_route_is_absent(monkeypatch, tmp_path):
    entries = {'/': [native_entry('a.txt', False)]}
    index = NoBatchIndex(existing_ids={doc_id(REPO, '/a.txt')})
    command, _ = _configure(monkeypatch, entries, index)
    err = StringIO()
    out = StringIO()
    command.Command(stdout=out, stderr=err).handle(
        repo_id=REPO, checkpoint=str(tmp_path / 'c.json'), max_pages=5, threshold=0.0)
    report = json.loads(out.getvalue())
    assert report['indexed_files'] == 1 and report['missing_files'] == 0
    assert index.get_calls == [doc_id(REPO, '/a.txt')]
    assert 'falling back' in err.getvalue()


def test_reconcile_exits_non_zero_below_the_file_coverage_threshold(monkeypatch, tmp_path):
    entries = {'/': [native_entry('a.txt', False)]}
    index = FakeIndex()
    command, _ = _configure(monkeypatch, entries, index)
    out = StringIO()
    with pytest.raises(SystemExit) as info:
        command.Command(stdout=out).handle(repo_id=REPO, checkpoint=str(tmp_path / 'c.json'),
                                           max_pages=5)
    assert info.value.code != 0
    # The summary is still emitted, so a gate failure is diagnosable.
    assert json.loads(out.getvalue())['coverage_ratio'] == 0.0


def test_reconcile_passes_when_coverage_meets_the_threshold(monkeypatch, tmp_path):
    entries = {'/': [native_entry('a.txt', False)]}
    index = FakeIndex(existing_ids={doc_id(REPO, '/a.txt')})
    command, _ = _configure(monkeypatch, entries, index)
    report = _run(command, StringIO(), checkpoint=str(tmp_path / 'c.json'), max_pages=5)
    assert report['coverage_ratio'] == 1.0


def test_reconcile_incomplete_traversal_exits_non_zero_unless_allowed(monkeypatch, tmp_path):
    entries = {'/': [native_entry('sub')], '/sub': [native_entry('deep')], '/sub/deep': []}
    index = FakeIndex(existing_ids={doc_id(REPO, '/sub'), doc_id(REPO, '/sub/deep')})
    command, _ = _configure(monkeypatch, entries, index)
    out = StringIO()
    with pytest.raises(SystemExit) as info:
        command.Command(stdout=out).handle(repo_id=REPO, checkpoint=str(tmp_path / 'c1.json'),
                                           max_pages=1, threshold=0.0)
    assert info.value.code != 0
    assert json.loads(out.getvalue())['complete'] is False
    # --allow-incomplete reports the same partial walk without failing the gate.
    report = _run(command, StringIO(), checkpoint=str(tmp_path / 'c2.json'),
                  max_pages=1, threshold=0.0, allow_incomplete=True)
    assert report['complete'] is False and report['pages'] == 1
    # Resuming the first checkpoint finishes the walk instead of restarting it.
    resumed = _run(command, StringIO(), checkpoint=str(tmp_path / 'c1.json'),
                   max_pages=100, threshold=0.0)
    assert resumed['complete'] is True and resumed['pages'] == 3


def test_reconcile_checkpoint_is_private_atomic_and_resumable(monkeypatch, tmp_path):
    entries = {'/': [native_entry('sub')], '/sub': []}
    index = FakeIndex()
    command, _ = _configure(monkeypatch, entries, index)
    checkpoint = tmp_path / 'c.json'
    _run(command, StringIO(), checkpoint=str(checkpoint), max_pages=5, threshold=0.0)
    assert stat.S_IMODE(checkpoint.stat().st_mode) == 0o600
    saved = json.loads(checkpoint.read_text())
    assert saved['repo_id'] == REPO and saved['head'] == HEAD and saved['pending'] == []
    assert saved['pages'] == 2 and saved['directories'] == 1 and saved['files'] == 0
    assert saved['indexed_dirs'] == 0 and saved['missing_dirs'] == 1
    assert saved['sample_missing'] == [{'path': '/sub', 'object_type': 'dir'}]
    # A resumed run trusts those counters and stays idempotent.
    report = _run(command, StringIO(), checkpoint=str(checkpoint), max_pages=5,
                  threshold=0.0)
    assert report['indexed_dirs'] == 0 and report['missing_dirs'] == 1


def test_reconcile_rejects_a_checkpoint_pinned_to_another_head_or_broken(monkeypatch, tmp_path):
    from django.core.management.base import CommandError
    command, _ = _configure(monkeypatch, {'/': []}, FakeIndex())
    base = dict(repo_id=REPO, head='b' * 40, pending=[dict(path='/', offset=0)], pages=0,
                directories=0, files=0, indexed_files=0, indexed_dirs=0,
                missing_files=0, missing_dirs=0, sample_missing=[])
    for index, state in enumerate([
            base,
            dict(base, head=HEAD, indexed_files=1),  # counters disagree with files
            dict(base, head=HEAD, missing_files=-1),
            dict(base, head=HEAD, sample_missing=[{'path': 1, 'object_type': 'file'}]),
            dict(base, head=HEAD, pending=[dict(path='relative', offset=0)])]):
        checkpoint = tmp_path / ('c%d.json' % index)
        checkpoint.write_text(json.dumps(state))
        with pytest.raises(CommandError, match='Checkpoint is invalid'):
            command.Command().handle(repo_id=REPO, checkpoint=str(checkpoint), max_pages=1)


def test_reconcile_aborts_when_the_library_head_changes_mid_walk(monkeypatch, tmp_path):
    from django.core.management.base import CommandError
    entries = {'/': [native_entry('sub')], '/sub': []}
    command, api = _configure(monkeypatch, entries, FakeIndex())
    calls = {'n': 0}

    def get_repo(repo_id):
        calls['n'] += 1
        return SimpleNamespace(head_cmmt_id=HEAD if calls['n'] < 3 else 'b' * 40)

    api.get_repo.side_effect = get_repo
    checkpoint = tmp_path / 'c.json'
    with pytest.raises(CommandError, match='Library changed'):
        command.Command().handle(repo_id=REPO, checkpoint=str(checkpoint), max_pages=5)
    # The aborted page is never checkpointed.
    assert not checkpoint.exists()


def test_reconcile_refuses_a_checkpoint_held_by_another_operator(monkeypatch, tmp_path):
    from django.core.management.base import CommandError
    command, _ = _configure(monkeypatch, {'/': []}, FakeIndex())
    checkpoint = tmp_path / 'c.json'
    with open(str(checkpoint) + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with pytest.raises(CommandError, match='already in use'):
                command.Command().handle(repo_id=REPO, checkpoint=str(checkpoint), max_pages=1)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def test_reconcile_stale_pass_reports_missing_native_paths_within_its_bound(monkeypatch, tmp_path):
    index = FakeIndex(repo_documents=[
        {'id': 'x1', 'path': '/gone.txt', 'object_type': 'file'},
        {'id': 'x2', 'path': '/kept.txt', 'object_type': 'file'},
        {'id': 'x3', 'path': '/also-gone', 'object_type': 'dir'}])
    command, api = _configure(monkeypatch, {'/': []}, index)
    api.get_file_id_by_path.side_effect = lambda r, p: 'id' if p == '/kept.txt' else None
    api.get_dir_id_by_path.side_effect = lambda r, p: None
    # --max-stale-checks bounds how many index documents are examined: with a
    # bound of 2 only the first two are inspected, so the third is never probed.
    report = _run(command, StringIO(), max_pages=1, threshold=0.0,
                  stale=True, max_stale_checks=2)
    assert report['stale'] == {'checked': 2, 'stale': [
        {'path': '/gone.txt', 'object_type': 'file'}]}
    # The sweep is off unless asked for, and a larger bound walks further.
    assert 'stale' not in _run(command, StringIO(), max_pages=1, threshold=0.0)
    wider = _run(command, StringIO(), max_pages=1, threshold=0.0,
                 stale=True, max_stale_checks=10)
    assert wider['stale'] == {'checked': 3, 'stale': [
        {'path': '/gone.txt', 'object_type': 'file'},
        {'path': '/also-gone', 'object_type': 'dir'}]}


def test_reconcile_rejects_invalid_arguments_before_touching_the_library(monkeypatch, tmp_path):
    from django.core.management.base import CommandError
    command, api = _configure(monkeypatch, {'/': []}, FakeIndex())
    for options, message in [
            (dict(max_pages=0), 'max-pages'),
            (dict(max_pages=101), 'max-pages'),
            (dict(threshold=1.5), 'threshold'),
            (dict(threshold=-0.1), 'threshold'),
            (dict(max_stale_checks=0), 'max-stale-checks')]:
        with pytest.raises(CommandError, match=message):
            command.Command().handle(repo_id=REPO, **options)
    assert api.get_repo.call_count == 0
