"""Explicit resumable repair; never enumerate a library inside a search request."""
import fcntl
import json
import os
import re
import time
from pathlib import Path
from uuid import UUID

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from cloudfile_ext.search.backfill import advance_page
from cloudfile_ext.search.backends.meilisearch import INDEX_NAME, client_from_settings
from cloudfile_ext.search.indexer import _build_document


class Command(BaseCommand):
    help = 'Backfill directory names into the legacy Meili index in bounded resumable batches.'

    def add_arguments(self, parser):
        parser.add_argument('--repo-id', required=True)
        parser.add_argument('--checkpoint', required=True)
        parser.add_argument('--max-pages', type=int, default=10)

    def handle(self, *args, **options):
        from seaserv import seafile_api
        if getattr(settings, 'CF_PROVIDER_SEARCH', '') != 'meilisearch':
            raise CommandError('Meilisearch provider must be enabled.')
        try:
            repo_id = str(UUID(options['repo_id']))
        except ValueError:
            raise CommandError('Invalid library ID.') from None
        if not 1 <= options['max_pages'] <= 100:
            raise CommandError('max-pages must be between 1 and 100.')
        checkpoint = Path(options['checkpoint']).expanduser().resolve()
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        # A shared checkpoint must not be advanced by two operators concurrently.
        with open(str(checkpoint) + '.lock', 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CommandError('This checkpoint is already in use.') from None
            repo = seafile_api.get_repo(repo_id)
            head = getattr(repo, 'head_cmmt_id', None)
            if not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40}', head):
                raise CommandError('Library snapshot is unavailable.')
            state = dict(repo_id=repo_id, head=head, pending=[dict(path='/', offset=0)], pages=0, directories=0)
            if checkpoint.exists():
                try:
                    if checkpoint.stat().st_size > 1048576:
                        raise ValueError()
                    state = json.loads(checkpoint.read_text())
                    # Validate counters as well as paths before trusting operator progress.
                    if (any(type(state.get(key)) is not int or state[key] < 0 for key in ('pages', 'directories'))
                            or state['repo_id'] != repo_id or state['head'] != head or not isinstance(state['pending'], list)
                            or len(state['pending']) > 10000 or any(not isinstance(p, dict)
                            or not isinstance(p.get('path'), str) or not p['path'].startswith('/')
                            or '\0' in p['path'] or '//' in p['path'] or len(p['path'].encode('utf-8')) > 4096
                            or any(part in ('.', '..') for part in p['path'].split('/'))
                            or type(p.get('offset')) is not int or not 0 <= p['offset'] <= 2 ** 31 - 102 for p in state['pending'])):
                        raise ValueError()
                except (ValueError, KeyError, TypeError):
                    raise CommandError('Checkpoint is invalid or library changed; use a new checkpoint.') from None
            client = client_from_settings()
            client.ensure_index()

            def assert_current():
                current = seafile_api.get_repo(repo_id)
                if current is None or current.head_cmmt_id != head:
                    raise CommandError('Library changed; restart with a new checkpoint.')

            def write_documents(documents):
                task = client._call('PUT', '/indexes/%s/documents' % INDEX_NAME, documents)
                uid = task.get('taskUid') if isinstance(task, dict) else None
                if type(uid) is not int or uid < 0:
                    raise CommandError('Index write was not acknowledged.')
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    result = client._call('GET', '/tasks/%d' % uid)
                    if result.get('status') == 'succeeded':
                        return
                    if result.get('status') not in ('enqueued', 'processing'):
                        raise CommandError('Index write failed; checkpoint was not advanced.')
                    time.sleep(0.1)
                raise CommandError('Index write pending; rerun the same checkpoint to retry safely.')

            for _ in range(options['max_pages']):
                if not state['pending']:
                    break
                state = advance_page(state,
                    read_page=lambda path, offset, limit: seafile_api.list_dir_by_commit_and_path(repo_id, head, path, offset, limit),
                    build_document=lambda path, mtime: _build_document(repo_id, path, '', mtime, 0, 'dir'),
                    write_documents=write_documents, assert_current=assert_current)
                # Atomic progress records only paths/offsets, never credentials.
                temp = checkpoint.with_name(checkpoint.name + '.tmp')
                with open(temp, 'w') as output:
                    os.fchmod(output.fileno(), 0o600)
                    json.dump(state, output)
                os.replace(temp, checkpoint)
            self.stdout.write('pages=%d directories=%d complete=%s' %
                (state['pages'], state['directories'], not state['pending']))
