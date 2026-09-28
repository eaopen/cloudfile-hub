# -*- coding: utf-8 -*-
"""Bounded external-tree scanning for the CloudFile Meilisearch index.

The scanner owns neither the source bytes nor a second catalogue of them. Its
only durable state is a queue of directories still to inspect; every file
document is recreated from the mounted tree and carries the source's synthetic
repo id. A queue is used instead of a recursive walk so one slow NAS cannot
hold the single cf-worker loop hostage.
"""

import json
import logging
import posixpath

from cloudfile_ext.external_sources import service
from cloudfile_ext.external_sources.providers import SourceError

logger = logging.getLogger(__name__)

TASK_NAME = 'external_source_scan'
DEFAULT_DIRS_PER_TICK = 20
DEFAULT_FILES_PER_TICK = 2000


def _detail_queue(detail):
    try:
        value = json.loads(detail or '{}')
        queue = value.get('queue')
        if isinstance(queue, list) and all(isinstance(item, str) for item in queue):
            return queue
    except (TypeError, ValueError):
        pass
    return ['/']


def _join(parent, name):
    return '/' + name if parent == '/' else posixpath.join(parent, name)


def _doc_id(repo_id, path):
    from cloudfile_ext.search.indexer import _doc_id as native_doc_id
    return native_doc_id(repo_id, path)


def _document(source, entry, path):
    name = entry.name
    extension = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    return {
        'id': _doc_id(source.repo_id, path),
        'repo_id': source.repo_id,
        'path': path,
        'name': name,
        'extension': extension,
        'object_type': 'file',
        'size': entry.size,
        'mtime': entry.mtime,
        'last_modifier': '',
        'content': '',
        'external_source_id': source.id,
    }


def scan_source(source, client, dirs_per_tick=DEFAULT_DIRS_PER_TICK,
                files_per_tick=DEFAULT_FILES_PER_TICK):
    """Scan at most a bounded slice and persist its remaining directory queue.

    A completed pass starts its next cycle at the root. Deleting the source's
    prior documents at that boundary is intentional: it lets deleted NAS files
    disappear without maintaining a second file inventory table. During a new
    pass results grow back incrementally, never requiring an unbounded scan.
    """
    from cloudfile_ext.external_sources.models import ExternalScanState

    state = ExternalScanState.objects.get_state(source.id)
    queue = _detail_queue(state.detail if state else '')
    # An error retains its queue. Clearing the index on every retry would make
    # a transient NAS outage hide all previously indexed files indefinitely.
    new_cycle = not state or state.status == 'complete'
    if new_cycle:
        try:
            client.delete_by_repo(source.repo_id)
        except Exception:
            logger.exception('external source scan: cannot clear %s', source.name)
            ExternalScanState.objects.save_state(source.id, '/', 'error',
                                                  json.dumps({'queue': queue}))
            return False

    backend = service.backend_for(source)
    documents = []
    last_path = '/'
    try:
        for _unused in range(max(1, dirs_per_tick)):
            if not queue or len(documents) >= files_per_tick:
                break
            directory = queue.pop(0)
            last_path = directory
            for entry in backend.list_dir(source.root_path, directory):
                path = _join(directory, entry.name)
                if entry.is_dir:
                    queue.append(path)
                elif len(documents) < files_per_tick:
                    documents.append(_document(source, entry, path))
    except SourceError as exc:
        logger.warning('external source scan: %s unavailable: %s', source.name, exc)
        queue.insert(0, last_path)
        ExternalScanState.objects.save_state(source.id, last_path, 'error',
                                              json.dumps({'queue': queue}))
        return False

    try:
        if documents:
            client.upsert_documents(documents)
    except Exception:
        logger.exception('external source scan: failed writing documents for %s', source.name)
        ExternalScanState.objects.save_state(source.id, last_path, 'error',
                                              json.dumps({'queue': queue}))
        return False

    status = 'complete' if not queue else 'running'
    ExternalScanState.objects.save_state(source.id, last_path, status,
                                          json.dumps({'queue': queue}))
    return True


def scan_tick(client=None, dirs_per_tick=None, files_per_tick=None):
    """Run one bounded slice for every enabled source.

    The task is registered only with the Meilisearch provider, because
    SeaSearch owns its own index and has no supported external-document write
    protocol.
    """
    from django.conf import settings
    from cloudfile_ext.external_sources.models import ExternalSource
    from cloudfile_ext.search.backends.meilisearch import client_from_settings

    client = client or client_from_settings()
    dirs_per_tick = dirs_per_tick or getattr(settings, 'CF_EXTERNAL_SCAN_MAX_DIRS',
                                              DEFAULT_DIRS_PER_TICK)
    files_per_tick = files_per_tick or getattr(settings, 'CF_EXTERNAL_SCAN_MAX_FILES',
                                                DEFAULT_FILES_PER_TICK)
    try:
        dirs_per_tick = max(1, int(dirs_per_tick))
        files_per_tick = max(1, int(files_per_tick))
    except (TypeError, ValueError):
        logger.warning('invalid external scan limits; using defaults')
        dirs_per_tick = DEFAULT_DIRS_PER_TICK
        files_per_tick = DEFAULT_FILES_PER_TICK
    client.ensure_index()
    for source in ExternalSource.objects.enabled_sources():
        scan_source(source, client, dirs_per_tick, files_per_tick)
