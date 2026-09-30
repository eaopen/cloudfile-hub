"""Adapt native scan metadata without inferring progress from authorized rows."""
import json
import logging
import re
import stat
from typing import NamedTuple
from types import SimpleNamespace

logger = logging.getLogger(__name__)


class DirectoryPageError(Exception):
    """Unavailable or inconsistent native pagination must not look exhausted."""


class DirectoryRevisionChanged(DirectoryPageError):
    """The current path no longer resolves to the requested directory object."""


class DirectoryPage(NamedTuple):
    items: list
    dir_revision: str
    scanned_count: int
    scan_exhausted: bool
    next_scan_position: object


def _validate_directory_entry(entry):
    """Validate the wire fields emitted by native dirent_to_json, before use.

    All twelve fields are required, including nullable strings: absence must
    not acquire a default or escape as AttributeError in endpoint rendering.
    mode carries the POSIX kind, not a separate type/kind/name wire field.
    Signed integer widths follow lib/dirent.vala; bool is not a JSON integer.
    """
    integer_fields = {'mode': 32, 'version': 32, 'mtime': 64,
                      'size': 64, 'lock_time': 64}
    nullable_fields = ('modifier', 'permission', 'lock_owner')
    boolean_fields = ('is_locked', 'is_shared')
    required = {'obj_id', 'obj_name', *integer_fields,
                *nullable_fields, *boolean_fields}
    if not isinstance(entry, dict) or not required.issubset(entry):
        raise DirectoryPageError('Missing native directory entry fields')
    if (not isinstance(entry['obj_id'], str)
            or re.fullmatch(r'[0-9a-f]{40}', entry['obj_id']) is None
            or not isinstance(entry['obj_name'], str)):
        raise DirectoryPageError('Invalid native directory entry identity')
    for field, bits in integer_fields.items():
        value = entry[field]
        if type(value) is not int or not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
            raise DirectoryPageError('Invalid native directory entry integer')
    if entry['mode'] < 0 or stat.S_IFMT(entry['mode']) not in (stat.S_IFDIR, stat.S_IFREG):
        raise DirectoryPageError('Invalid native directory entry kind')
    for field in nullable_fields:
        # The native s:s? serializer preserves null, notably legacy file and
        # directory modifiers and the default unlocked owner. Do not coerce it.
        if entry[field] is not None and not isinstance(entry[field], str):
            raise DirectoryPageError('Invalid native directory entry string')
    if any(type(entry[field]) is not bool for field in boolean_fields):
        raise DirectoryPageError('Invalid native directory entry boolean')


def read_directory_page(api, repo_id, path, revision, user, start, limit):
    """Read exactly one raw window; empty authorized pages may continue.

    No fallback to list_dir_with_perm: that RPC has already lost scan state.
    The endpoint still owns request and parent permission validation.
    """
    try:
        raw = api.cf_list_dir_page(repo_id, path, revision, user, start, limit)
        data = json.loads(raw)
    except Exception as error:
        raise DirectoryPageError('Native directory pagination unavailable') from error
    if not isinstance(data, dict):
        raise DirectoryPageError('Invalid native directory page')
    if data.get('error') == 'DIR_REVISION_CHANGED':
        raise DirectoryRevisionChanged('Folder changed; restart paging.')

    entries = data.get('visible_items')
    scanned = data.get('scanned_count')
    exhausted = data.get('scan_exhausted')
    next_position = data.get('next_scan_position')
    # Validate the envelope, never use len(entries) to infer an end or cursor.
    if (data.get('dir_revision') != revision or not isinstance(entries, list)
            or type(scanned) is not int or not 0 <= scanned <= limit
            or type(exhausted) is not bool or len(entries) > scanned
            or type(data.get('visible_count')) is not int
            or data['visible_count'] != len(entries)
            or 'next_scan_position' not in data
            or (exhausted and next_position is not None)
            or (not exhausted and (scanned != limit or type(next_position) is not int
                                   or next_position != start + scanned
                                   or next_position <= start))):
        raise DirectoryPageError('Invalid native directory scan state')
    # Reject the whole page before constructing presentation objects, so a
    # malformed later row cannot produce either a partial page or HTTP 500.
    for entry in entries:
        _validate_directory_entry(entry)

    logger.debug('CloudFile directory page: scanned_count=%d visible_count=%d '
                 'next_cursor=%s scan_exhausted=%s',
                 scanned, len(entries), next_position, exhausted)
    return DirectoryPage([SimpleNamespace(**entry) for entry in entries],
                         revision, scanned, exhausted, next_position)
