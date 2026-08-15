# -*- coding: utf-8 -*-
"""cf-worker periodic task: feed seafevents' Activity stream into Meilisearch.

Registered only when CF_PROVIDER_SEARCH = 'meilisearch'
(cloudfile_ext.search.register). Reads the same Activity table
cloudfile_ext.audit already reads -- seafevents diffs every committed tree and
persists file/directory changes there, so consuming it here means not forking
seafevents for a second index (docs/search.md section four: "索引侧走
cf-worker，不 fork seafevents").

Scope (v1, see docs/search.md): files only, not directories. Content is
indexed for plain-text files up to CF_SEARCH_INDEX_TEXT_MAX_BYTES; every other
type is indexed by filename/path/metadata only. Binary content extraction
(docx/pdf/xlsx...) is what SeaSearch already does through seafevents --
duplicating that pipeline for the one backend that exists specifically for
sites not running SeaSearch would be the tail wagging the dog.
"""

import json
import logging
import urllib.error
import urllib.request

from django.db import connection

logger = logging.getLogger(__name__)

#: How many Activity rows one tick will walk at most. Keeps a single tick
#: short -- cf_worker runs its registered tasks one after another, so a slow
#: task delays every task behind it
#: (cloudfile_ext.management.commands.cf_worker). A backlog larger than this
#: is simply drained over several ticks.
BATCH_SIZE = 500

#: Activity.op_type values that touch a file's content or existence. Activity
#: also carries library lifecycle rows (see cloudfile_ext.audit.views); those
#: fall outside this set and outside obj_type == 'file', so they are skipped
#: by the same filter without needing a separate check.
_FILE_OPS = frozenset(('create', 'edit', 'delete', 'rename', 'move', 'recover'))

TASK_NAME = 'search_meilisearch_index'
_STATE_NAME = 'meilisearch'




from cloudfile_ext.search.ops import doc_id as _doc_id, normalize_op as _normalize_op


def _text_extensions():
    from seahub.search.utils import SEARCH_FILEEXT
    from seahub.utils.file_types import TEXT
    return frozenset(SEARCH_FILEEXT[TEXT])


def _fetch_content(repo, file_id, path, max_bytes):
    """Best-effort plain-text content, or '' if unavailable/too large/binary.

    Reads through the internal fileserver URL the same way
    seahub.thumbnail.utils generates previews -- the one already-proven way to
    pull a file's bytes from inside Seahub without re-deriving Seafile's
    block-assembly logic. Username is '' (system access): this runs in the
    background worker, not on behalf of any particular request, matching how
    thumbnail generation itself requests a token.
    """
    from seaserv import seafile_api
    from seahub.utils import gen_inner_file_get_url

    name = path.rsplit('/', 1)[-1]
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    if ext not in _text_extensions():
        return ''
    size = seafile_api.get_file_size(repo.store_id, repo.version, file_id)
    if size is None or size > max_bytes:
        return ''
    try:
        token = seafile_api.get_fileserver_access_token(
            repo.id, file_id, 'view', '', use_onetime=True)
        if not token:
            return ''
        inner_url = gen_inner_file_get_url(token, name)
        with urllib.request.urlopen(inner_url, timeout=10) as resp:
            raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return ''
        return raw.decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError, ValueError):
        logger.warning('meilisearch indexer: could not read %s/%s',
                       repo.id, path, exc_info=True)
        return ''


def _fetch_tags(repo_id, path):
    """Best-effort tag names for a file, or [] when unavailable.

    Tags live in Seahub's FileTags table keyed by a UUID map; a freshly
    committed file may not have a mapping yet, and a tag lookup failing must
    not fail indexing.
    """
    try:
        from seahub.file_tags.models import FileTags
        return [t['tag_name'] for t in
                FileTags.objects.get_file_tag_by_path(repo_id, path)]
    except Exception:
        logger.warning('meilisearch indexer: could not read tags for %s/%s',
                       repo_id, path, exc_info=True)
        return []


def _build_document(repo_id, path, op_user, timestamp, max_bytes):
    from seaserv import seafile_api

    repo = seafile_api.get_repo(repo_id)
    if not repo:
        return None
    file_id = seafile_api.get_file_id_by_path(repo_id, path)
    if not file_id:
        # Deleted or moved again since this Activity row was written -- the
        # row for whatever happened next supersedes this one.
        return None
    size = seafile_api.get_file_size(repo.store_id, repo.version, file_id) or 0
    name = path.rsplit('/', 1)[-1]
    extension = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    try:
        creator = seafile_api.get_repo_owner(repo_id) or ''
    except Exception:
        logger.warning('meilisearch indexer: could not read owner for %s',
                       repo_id, exc_info=True)
        creator = ''
    return {
        'id': _doc_id(repo_id, path),
        'repo_id': repo_id,
        'path': path,
        'name': name,
        'extension': extension,
        'object_type': 'file',
        'size': size,
        'mtime': timestamp,
        'last_modifier': op_user,
        'creator': creator,
        'tags': _fetch_tags(repo_id, path),
        'content': _fetch_content(repo, file_id, path, max_bytes),
    }


def _activities_since(cursor, limit):
    with connection.cursor() as db_cursor:
        db_cursor.execute(
            'SELECT id, op_type, obj_type, op_user, timestamp, repo_id, path, '
            'detail FROM Activity WHERE id > %s ORDER BY id ASC LIMIT %s',
            [cursor, limit])
        rows = db_cursor.fetchall()
    events = []
    for row in rows:
        events.append({
            'id': row[0], 'op_type': row[1], 'obj_type': row[2],
            'op_user': row[3], 'timestamp': row[4], 'repo_id': row[5],
            'path': row[6], 'detail': json.loads(row[7] or '{}'),
        })
    return events


def index_tick(client=None, max_bytes=None):
    """One pass: consume Activity rows since the last watermark.

    `client`/`max_bytes` are injection points for tests; production calls take
    both from settings.
    """
    from django.conf import settings
    from cloudfile_ext.search.backends.meilisearch import (
        MeilisearchError, client_from_settings,
    )
    from cloudfile_ext.search.models import SearchIndexState

    client = client or client_from_settings()
    max_bytes = max_bytes if max_bytes is not None else getattr(
        settings, 'CF_SEARCH_INDEX_TEXT_MAX_BYTES', 1024 * 1024)

    cursor = SearchIndexState.objects.get_cursor(_STATE_NAME)
    events = _activities_since(cursor, BATCH_SIZE)
    if not events:
        return

    try:
        client.ensure_index()
    except MeilisearchError:
        logger.exception('meilisearch indexer: ensure_index failed; skipping tick')
        return

    upserts = {}
    deletes = set()
    for event in events:
        op_type = _normalize_op(event['op_type'])
        if op_type not in _FILE_OPS or event['obj_type'] != 'file':
            continue
        repo_id = event['repo_id']

        # seafevents merges consecutive commits of one op into a single
        # Activity row whose detail is a list of the individual items (each
        # with its own path / old_path). Expand it; single-op rows carry the
        # path on the row itself.
        detail = event['detail']
        if isinstance(detail, list):
            entries = [(it.get('path'), it.get('old_path'))
                       for it in detail if isinstance(it, dict)]
        elif isinstance(detail, dict):
            entries = [(event['path'], detail.get('old_path'))]
        else:
            entries = [(event['path'], None)]

        for path, old_path in entries:
            if not path:
                continue
            if op_type == 'delete':
                doc_id = _doc_id(repo_id, path)
                deletes.add(doc_id)
                upserts.pop(doc_id, None)
                continue

            if op_type in ('rename', 'move') and old_path:
                old_id = _doc_id(repo_id, old_path)
                deletes.add(old_id)
                upserts.pop(old_id, None)

            doc = _build_document(repo_id, path, event['op_user'],
                                  event['timestamp'], max_bytes)
            if doc is None:
                deletes.add(_doc_id(repo_id, path))
            else:
                upserts[doc['id']] = doc
                deletes.discard(doc['id'])

    try:
        if upserts:
            client.upsert_documents(list(upserts.values()))
        if deletes:
            client.delete_documents(deletes)
    except MeilisearchError:
        # Do not advance the watermark on a failed write -- the next tick
        # retries the same batch. Losing documents silently would be worse
        # than reprocessing a few extra rows.
        logger.exception('meilisearch indexer: write failed; watermark not advanced')
        SearchIndexState.objects.advance(
            _STATE_NAME, cursor, 'error',
            'write failed at tick starting after id %s' % cursor)
        return

    last_id = events[-1]['id']
    SearchIndexState.objects.advance(_STATE_NAME, last_id, 'ok')
