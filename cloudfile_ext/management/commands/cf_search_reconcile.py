"""Bounded, resumable completeness check for the legacy Meili index.

Read-only counterpart to ``cf_search_backfill_directories``. It walks one
library's native tree with the same head-pinned bounded pattern and reports how
many visited files and directories actually have a document in the legacy
``cloudfile_files`` index. It never writes to the index, never reads file
bodies, and prints one machine-readable JSON summary, so the same command can
serve as a standing completeness gate after a backfill.

The index is the legacy compatibility index only. This says nothing about the
new ``search.resources`` query path.
"""
import fcntl
import json
import os
import re
import sys
from pathlib import Path
from uuid import UUID

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from cloudfile_ext.search.backfill import advance_page
from cloudfile_ext.search.backends.meilisearch import client_from_settings
from cloudfile_ext.search.reconcile import (
    MAX_STALE_CHECKS, SAMPLE_MISSING_MAX, Reconciler, coverage_ratio,
    record_for, stale_documents,
)

#: Standing gate for the file coverage of one library. A handful of stale
#: historical documents is expected; a real regression moves the ratio well past
#: this, so the default fails a gate rather than tolerating a partial backfill.
_DEFAULT_THRESHOLD = 0.999

#: Index documents one --stale sweep inspects by default. The sweep is an
#: operator diagnostic, not a per-run obligation, so the default stays small.
_DEFAULT_MAX_STALE_CHECKS = 200

_MAX_PAGES = 100
_MAX_CHECKPOINT_BYTES = 1048576
_HEAD_RE = re.compile(r'[0-9a-f]{40}\Z')


def _path_exists(seafile_api, repo_id, document):
    """Native existence probe for one index document (used by --stale)."""
    path = document.get('path')
    if not isinstance(path, str) or not path.startswith('/'):
        return False
    if document.get('object_type') == 'dir':
        return bool(seafile_api.get_dir_id_by_path(repo_id, path))
    return bool(seafile_api.get_file_id_by_path(repo_id, path))


def _valid_pending(pending):
    if not isinstance(pending, list) or len(pending) > 10000:
        return False
    for position in pending:
        if (not isinstance(position, dict) or not isinstance(position.get('path'), str)
                or not position['path'].startswith('/') or '\0' in position['path']
                or '//' in position['path']
                or len(position['path'].encode('utf-8')) > 4096
                or any(part in ('.', '..') for part in position['path'].split('/'))
                or type(position.get('offset')) is not int
                or not 0 <= position['offset'] <= 2 ** 31 - 102):
            return False
    return True


def _validate_state(state, repo_id, head):
    """Reject a checkpoint that is corrupt or belongs to another library/head.

    The indexed+missing cross-check matters because the report (and the gate) is
    built from these counters: a checkpoint whose counters disagree with the
    pages it claims to have walked would silently misstate coverage.
    """
    if not isinstance(state, dict):
        raise ValueError()
    for key in ('pages', 'directories', 'files', 'indexed_files', 'indexed_dirs',
                'missing_files', 'missing_dirs'):
        if type(state.get(key)) is not int or state[key] < 0:
            raise ValueError()
    if state.get('repo_id') != repo_id or state.get('head') != head:
        raise ValueError()
    if not _valid_pending(state.get('pending')):
        raise ValueError()
    if (state['indexed_files'] + state['missing_files'] != state['files']
            or state['indexed_dirs'] + state['missing_dirs'] != state['directories']):
        raise ValueError()
    sample = state.get('sample_missing')
    if not isinstance(sample, list) or len(sample) > SAMPLE_MISSING_MAX:
        raise ValueError()
    if any(not isinstance(row, dict) or not isinstance(row.get('path'), str)
           or row.get('object_type') not in ('file', 'dir') for row in sample):
        raise ValueError()


class Command(BaseCommand):
    help = 'Report how much of one library is present in the legacy Meili index; never writes to it.'

    def add_arguments(self, parser):
        parser.add_argument('--repo-id', required=True)
        parser.add_argument('--checkpoint')
        parser.add_argument('--max-pages', type=int, default=10)
        parser.add_argument('--threshold', type=float, default=_DEFAULT_THRESHOLD)
        parser.add_argument('--allow-incomplete', action='store_true')
        parser.add_argument('--stale', action='store_true')
        parser.add_argument('--max-stale-checks', type=int,
                            default=_DEFAULT_MAX_STALE_CHECKS)

    def handle(self, *args, **options):
        from seaserv import seafile_api
        if getattr(settings, 'CF_PROVIDER_SEARCH', '') != 'meilisearch':
            raise CommandError('Meilisearch provider must be enabled.')
        try:
            repo_id = str(UUID(options['repo_id']))
        except ValueError:
            raise CommandError('Invalid library ID.') from None
        max_pages = options.get('max_pages', 10)
        if type(max_pages) is not int or not 1 <= max_pages <= _MAX_PAGES:
            raise CommandError('max-pages must be between 1 and 100.')
        threshold = options.get('threshold', _DEFAULT_THRESHOLD)
        if type(threshold) not in (int, float) or not 0.0 <= threshold <= 1.0:
            raise CommandError('threshold must be between 0 and 1.')
        max_stale_checks = options.get('max_stale_checks', _DEFAULT_MAX_STALE_CHECKS)
        if type(max_stale_checks) is not int or not 1 <= max_stale_checks <= MAX_STALE_CHECKS:
            raise CommandError('max-stale-checks must be between 1 and %d.' % MAX_STALE_CHECKS)

        checkpoint = None
        lock = None
        if options.get('checkpoint'):
            checkpoint = Path(options['checkpoint']).expanduser().resolve()
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            # One operator per checkpoint: two concurrent walks would each
            # report a different partial truth and overwrite the other's cursor.
            lock = open(str(checkpoint) + '.lock', 'a')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CommandError('This checkpoint is already in use.') from None

        repo = seafile_api.get_repo(repo_id)
        head = getattr(repo, 'head_cmmt_id', None)
        if not isinstance(head, str) or not _HEAD_RE.match(head):
            raise CommandError('Library snapshot is unavailable.')

        state = dict(repo_id=repo_id, head=head, pending=[dict(path='/', offset=0)],
                     pages=0, directories=0, files=0,
                     indexed_files=0, indexed_dirs=0, missing_files=0,
                     missing_dirs=0, sample_missing=[])
        if checkpoint is not None and checkpoint.exists():
            try:
                if checkpoint.stat().st_size > _MAX_CHECKPOINT_BYTES:
                    raise ValueError()
                state = json.loads(checkpoint.read_text())
                _validate_state(state, repo_id, head)
            except (ValueError, KeyError, TypeError):
                raise CommandError('Checkpoint is invalid or library changed; use a new checkpoint.') from None

        # No ensure_index(): this command is read-only and must not create or
        # reconfigure anything, including on an index that does not exist yet.
        client = client_from_settings()
        reconciler = Reconciler(repo_id, client)
        reconciler.restore(state)
        if reconciler.probe() != 'batch':
            self.stderr.write('documents/fetch unavailable; falling back to per-document GET.')

        def build_document(path, mtime, object_type, entry):
            return record_for(repo_id, path, object_type)

        def assert_current():
            current = seafile_api.get_repo(repo_id)
            if current is None or current.head_cmmt_id != head:
                raise CommandError('Library changed; restart with a new checkpoint.')

        def save_checkpoint():
            if checkpoint is None:
                return
            state.update(reconciler.snapshot())
            temp = checkpoint.with_name(checkpoint.name + '.tmp')
            with open(temp, 'w') as output:
                os.fchmod(output.fileno(), 0o600)
                json.dump(state, output)
            os.replace(temp, checkpoint)

        for _ in range(max_pages):
            if not state['pending']:
                break
            state = advance_page(state,
                read_page=lambda path, offset, limit: seafile_api.list_dir_by_commit_and_path(
                    repo_id, head, path, offset, limit),
                build_document=build_document,
                # Existence is settled inside the page callback, so a checkpoint
                # is only ever written for entries that already have an answer.
                write_documents=reconciler.check_page,
                assert_current=assert_current, kinds=('dir', 'file'))
            save_checkpoint()
        save_checkpoint()

        complete = not state['pending']
        ratio = coverage_ratio(reconciler.indexed_files, state['files'])
        report = {
            'repo_id': repo_id,
            'head': head,
            'native_files': state['files'],
            'native_dirs': state['directories'],
            'indexed_files': reconciler.indexed_files,
            'indexed_dirs': reconciler.indexed_dirs,
            'missing_files': reconciler.missing_files,
            'missing_dirs': reconciler.missing_dirs,
            'coverage_ratio': round(ratio, 6),
            'sample_missing': reconciler.sample_missing,
            'pages': state['pages'],
            'complete': complete,
        }
        if options.get('stale'):
            report['stale'] = stale_documents(
                client, repo_id, max_checks=max_stale_checks,
                path_exists=lambda document: _path_exists(seafile_api, repo_id, document))

        # Only the summary goes to stdout, and it never carries credentials,
        # cursor internals or document bodies -- just counts and paths.
        self.stdout.write(json.dumps(report))

        # Release the checkpoint before failing: a gate exit must not leave the
        # lock held for the next run against the same checkpoint.
        exit_code = 0
        if not complete and not options.get('allow_incomplete'):
            exit_code = 2
        elif complete and ratio < threshold:
            exit_code = 3
        if lock is not None:
            lock.close()
        if exit_code:
            raise SystemExit(exit_code)
