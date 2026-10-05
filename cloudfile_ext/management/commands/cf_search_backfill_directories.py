"""Explicit resumable repair; never enumerate a library inside a search request."""
import fcntl
import json
import logging
import os
import re
import time
from pathlib import Path
from uuid import UUID

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from cloudfile_ext.search.backfill import advance_page
from cloudfile_ext.search.backends.meilisearch import INDEX_NAME, client_from_settings
from cloudfile_ext.search.indexer import (
    _build_document, backfill_entry_is_usable, build_backfill_document,
    preload_tags,
)

logger = logging.getLogger(__name__)


#: --kinds selects what one run indexes. The legacy index has no file-level
#: backfill otherwise: only Activity rows exist, and they cover part of a library.
_KINDS = {'dir': ('dir',), 'file': ('file',), 'all': ('dir', 'file')}

#: Documents held in memory before one Meili write. Directory-heavy libraries
#: average only a handful of documents per native page, so waiting for one
#: async task per page makes the write round-trip the whole cost. The buffer is
#: also the memory bound: it never exceeds this plus one page of 100 documents.
_FLUSH_DOCS = 500
_FLUSH_DOCS_MIN = 1
_FLUSH_DOCS_MAX = 2000


class Command(BaseCommand):
    help = 'Backfill directory and/or file metadata into the legacy Meili index in bounded resumable batches.'

    def add_arguments(self, parser):
        parser.add_argument('--repo-id', required=True)
        parser.add_argument('--checkpoint', required=True)
        parser.add_argument('--max-pages', type=int, default=10)
        parser.add_argument('--kinds', choices=sorted(_KINDS), default='dir')
        parser.add_argument('--flush-docs', type=int, default=_FLUSH_DOCS)

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
        flush_docs = options.get('flush_docs', _FLUSH_DOCS)
        if type(flush_docs) is not int or not _FLUSH_DOCS_MIN <= flush_docs <= _FLUSH_DOCS_MAX:
            raise CommandError('flush-docs must be between 1 and 2000.')
        kinds = _KINDS.get(options.get('kinds') or 'dir')
        if kinds is None:
            raise CommandError('kinds must be one of dir, file or all.')
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
            state = dict(repo_id=repo_id, head=head, pending=[dict(path='/', offset=0)],
                         pages=0, directories=0, files=0)
            if checkpoint.exists():
                try:
                    if checkpoint.stat().st_size > 1048576:
                        raise ValueError()
                    state = json.loads(checkpoint.read_text())
                    # Validate counters as well as paths before trusting operator progress.
                    if (any(type(state.get(key)) is not int or state[key] < 0 for key in ('pages', 'directories', 'files'))
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

            # One preload replaces the per-document tag lookup, which measured
            # ~26 ms a call against a few dozen tag rows -- the whole backfill
            # ran at ~20 files/s because of it. A failure here falls back to
            # exactly the old per-path lookups rather than indexing documents
            # with silently empty tags.
            try:
                file_tags, dir_tags = preload_tags(repo_id)
            except Exception:
                logger.warning('search backfill: tag preload failed for %s; '
                               'falling back to per-path lookups', repo_id,
                               exc_info=True)
                file_tags = dir_tags = None

            # `_build_document` resolves the owner per document; a run indexes
            # one library, so one lookup at the start is enough for every
            # document built from a native entry. Failure degrades to '' exactly
            # as the per-document path does.
            try:
                creator = seafile_api.get_repo_owner(repo_id) or ''
            except Exception:
                logger.warning('search backfill: could not read owner for %s',
                               repo_id, exc_info=True)
                creator = ''

            # `advance_page` hands canonical paths ('/a/b', no trailing slash),
            # which is exactly what the preloaded map is keyed by.
            def build_document(path, mtime, object_type, entry):
                if file_tags is None:
                    return _build_document(repo_id, path, '', mtime, 0, object_type)
                if object_type in ('dir', 'folder'):
                    tags = dir_tags.get(path, [])
                else:
                    tags = file_tags.get(path, [])
                # The native entry already carries obj_id/size/mtime, so the
                # common case needs no per-file RPC at all. A file entry missing
                # a usable size is the one shape that cannot be trusted, and it
                # falls back to the RPC-based builder rather than indexing a
                # wrong size.
                if backfill_entry_is_usable(entry, object_type):
                    return build_backfill_document(
                        repo_id, path, entry, object_type, tags, creator)
                return _build_document(repo_id, path, '', mtime, 0, object_type, tags=tags)

            def assert_current():
                current = seafile_api.get_repo(repo_id)
                if current is None or current.head_cmmt_id != head:
                    raise CommandError('Library changed; restart with a new checkpoint.')

            # The buffer is the only place documents live until a flush lands.
            # advance_page hands us each page's documents; batching them here
            # turns one Meili PUT+wait per page into one per --flush-docs.
            buffer = []

            def write_documents(documents):
                buffer.extend(documents)

            def flush():
                if not buffer:
                    return
                task = client._call('PUT', '/indexes/%s/documents' % INDEX_NAME, list(buffer))
                uid = task.get('taskUid') if isinstance(task, dict) else None
                if type(uid) is not int or uid < 0:
                    raise CommandError('Index write was not acknowledged.')
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    result = client._call('GET', '/tasks/%d' % uid)
                    if result.get('status') == 'succeeded':
                        del buffer[:]
                        return
                    if result.get('status') not in ('enqueued', 'processing'):
                        raise CommandError('Index write failed; checkpoint was not advanced.')
                    time.sleep(0.1)
                raise CommandError('Index write pending; rerun the same checkpoint to retry safely.')

            def save_checkpoint():
                # Atomic progress records only paths/offsets, never credentials.
                temp = checkpoint.with_name(checkpoint.name + '.tmp')
                with open(temp, 'w') as output:
                    os.fchmod(output.fileno(), 0o600)
                    json.dump(state, output)
                os.replace(temp, checkpoint)

            for _ in range(options['max_pages']):
                if not state['pending']:
                    break
                state = advance_page(state,
                    read_page=lambda path, offset, limit: seafile_api.list_dir_by_commit_and_path(repo_id, head, path, offset, limit),
                    # max_bytes=0 keeps repair metadata-only: a page of file
                    # bodies would blow the Meili payload limit and stall the
                    # checkpoint. Files never carry an op_user here.
                    build_document=build_document,
                    write_documents=write_documents, assert_current=assert_current, kinds=kinds)
                if len(buffer) >= flush_docs:
                    flush()
                    # Durable only now: the on-disk checkpoint must never claim
                    # pages whose documents are still buffered or unwritten.
                    save_checkpoint()
            # Whatever the last pages produced is flushed before the checkpoint
            # that reports it, including a run that ended on max-pages.
            flush()
            save_checkpoint()
            self.stdout.write('pages=%d directories=%d files=%d complete=%s' %
                (state['pages'], state['directories'], state['files'], not state['pending']))
