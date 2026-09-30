"""Strict wire budgets, independent of Django and native dependencies."""
import json
from uuid import UUID

from cloudfile_extensions.resources.paths import normalize_path

VERSION = 1
MODEL = 'legacy-file-tag'
MAX_ITEMS = 50
MAX_BYTES = 65536
MAX_PATH_BYTES = 4096
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate field')
        result[key] = value
    return result


def request_body(raw):
    # Validate the complete envelope before any lookup, never accept a second
    # repo/identity supplied by an individual item or normalize dot segments.
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Request byte budget exceeded')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_object)
    if (not isinstance(value, dict) or set(value) != {'version', 'repo_id', 'items'} or
            type(value['version']) is not int or value['version'] != VERSION or
            not isinstance(value['repo_id'], str) or
            not isinstance(value['items'], list) or not 1 <= len(value['items']) <= MAX_ITEMS):
        raise ValueError('Invalid legacy tag batch')
    repo = str(UUID(value['repo_id']))
    items = []
    for item in value['items']:
        if not isinstance(item, dict) or set(item) != {'path', 'is_dir'} or type(item['is_dir']) is not bool:
            raise ValueError('Invalid item')
        path = normalize_path(item['path'], 'dir' if item['is_dir'] else 'file')
        if len(path.encode('utf-8')) > MAX_PATH_BYTES or len(path.split('/')) > 130:
            raise ValueError('Path budget exceeded')
        items.append((path, item['is_dir']))
    return repo, items


def capability():
    return dict(version=VERSION, model=MODEL, max_items=MAX_ITEMS,
                max_bytes=MAX_BYTES, max_path_bytes=MAX_PATH_BYTES)
