"""V2 read-only tag batch for authorized native CE files and directories.

This is one adapter over tag_reads.read(), not a second tag engine or cache.
A caller-supplied path must pass V2 ACL and current native object existence/type
checks before any tag binding is selected for the shared batched SQL read.
"""
import logging
import stat

from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from django.core.exceptions import RequestDataTooBig

from .acl_http import AuthenticatedACL
from .acl_policy import canonical_path
from .acl_runtime import Authority
from .acl_store import uuid
from .tag_reads import read as read_tags

logger = logging.getLogger(__name__)

VERSION = 2
MODEL = 'cloudfile-tag-read'
MAX_ITEMS = 200
MAX_BYTES = 65536
MAX_PATH_BYTES = 4096


def reply(data, status=200):
    result = Response(data, status=status)
    result['Cache-Control'] = 'no-store'
    return result


def _envelope(repo_id, rows):
    return dict(version=VERSION, model=MODEL, repo_id=repo_id, items=rows)


def _tag_row(path, kind, status, tags=None):
    return dict(path=path, is_dir=kind == 'dir', status=status, tags=tags)


def page_tags(repo_id, authorized_entries):
    """Inline tags for a pre-authorized native directory page, never full repo."""
    references = [(path, kind) for _, path, kind, _ in authorized_entries]
    try:
        tags = read_tags(repo_id, references)
        rows = [_tag_row(path, kind, 'OK', tags[(path, kind)]) for path, kind in references]
    except Exception:
        # Tag failure is display-only and never converts into an empty tag set.
        logger.exception('CloudFile directory page tag read unavailable')
        rows = [_tag_row(path, kind, 'FAILED') for path, kind in references]
    return _envelope(repo_id, rows)


def _valid_items(request):
    if len(request.body) > MAX_BYTES:
        raise ValueError('batch is too large')
    data = request.data
    if not isinstance(data, dict) or set(data) != {'version', 'repo_id', 'items'}:
        raise ValueError('invalid batch fields')
    if type(data['version']) is not int or data['version'] != VERSION:
        raise ValueError('invalid batch version')
    repo_id = uuid(data['repo_id'])
    items = data['items']
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise ValueError('invalid batch size')
    validated = []
    for item in items:
        if (not isinstance(item, dict) or set(item) != {'path', 'is_dir'}
                or type(item['is_dir']) is not bool):
            raise ValueError('invalid tag item')
        path = canonical_path(item['path'])
        if path == '/' or len(path.encode('utf-8')) > MAX_PATH_BYTES:
            raise ValueError('invalid path')
        validated.append((path, 'dir' if item['is_dir'] else 'file'))
    return repo_id, validated


def batch_tags(username, repo_id, references):
    """One Authority and one indexed tag read; native existence checks fail closed."""
    authority = Authority(username)
    unique = dict.fromkeys(references)
    outcome = {}
    visible = []
    for path, kind in unique:
        if not authority.effective(repo_id, path, kind).can_read:
            outcome[(path, kind)] = ('DENIED', None)
            continue
        native = authority.api.get_dirent_by_path(repo_id, path)
        if (native is None or not hasattr(native, 'mode') or
                (stat.S_ISDIR(native.mode) if kind == 'dir' else stat.S_ISREG(native.mode)) is False):
            outcome[(path, kind)] = ('NOT_FOUND', None)
            continue
        visible.append((path, kind))
    # Only existing, ACL-authorized paths participate in tag SQL.
    tags = read_tags(repo_id, visible)
    for ref in visible:
        outcome[ref] = ('OK', tags[ref])
    return _envelope(repo_id, [_tag_row(path, kind, *outcome[(path, kind)])
                               for path, kind in references])


class TagBatch(AuthenticatedACL):
    """GET capability; POST bounded current-user read across directory parents."""

    def initial(self, request, *args, **kwargs):
        # SessionAuthentication's CSRF check accesses DRF request.POST, which
        # can consume the JSON stream. Cache the bounded body before that check
        # so validation does not raise RawPostDataException for browser sessions.
        # Authentication and CSRF enforcement still run through the native path.
        if request.method == 'POST':
            try:
                size = int(request.META.get('CONTENT_LENGTH') or 0)
                if size > MAX_BYTES or len(request.body) > MAX_BYTES:
                    raise ValueError('batch is too large')
            except (ValueError, RequestDataTooBig):
                raise ValidationError({'code': 'INVALID_TAG_BATCH'}) from None
        return super().initial(request, *args, **kwargs)

    def get(self, request):
        if request.query_params:
            return reply({'code': 'INVALID_TAG_BATCH'}, 400)
        return reply(dict(version=VERSION, model=MODEL, max_items=MAX_ITEMS,
                          max_bytes=MAX_BYTES, max_path_bytes=MAX_PATH_BYTES))

    def post(self, request):
        try:
            repo_id, references = _valid_items(request)
        except (ValueError, KeyError, TypeError):
            return reply({'code': 'INVALID_TAG_BATCH'}, 400)
        try:
            return reply(batch_tags(request.user.username, repo_id, references))
        except PermissionError:
            return reply({'code': 'TAG_BATCH_DENIED'}, 403)
        except Exception:
            logger.exception('CloudFile authorized tag batch unavailable')
            return reply({'code': 'TAG_BATCH_UNAVAILABLE'}, 503)
