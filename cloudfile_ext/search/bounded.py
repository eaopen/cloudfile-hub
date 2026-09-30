"""Meili-first library search. Native fallback reads one directory page only.

The legacy native search RPC recursively walks an entire library. Never call
it here: an unavailable index must not turn a bounded query into a tree scan.
"""
import json
import posixpath
import stat
import time
from uuid import UUID

from cloudfile_extensions.resources.paths import normalize_path
from .backends.meilisearch import INDEX_NAME, MeilisearchError, _matched_tags


class SearchFailure(Exception):
    def __init__(self, code, message, status=503):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


def validate(repo_id, q, path, limit):
    try:
        repo = str(UUID(repo_id))
        directory = normalize_path(path or '/', 'dir')
        if not isinstance(q, str) or not q.strip() or len(q) > 512:
            raise ValueError()
        q.encode('utf-8')
        if len(directory.encode('utf-8')) > 4096 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError()
        return repo, q.strip(), directory, limit
    except Exception:
        raise SearchFailure('INVALID_SEARCH', 'Invalid search parameters', 400) from None


def query_page(*, repo_id, q, path, limit, offset, provider, client,
               list_directory, resolve_item, can_read, prepare_paths=None):
    """Candidates never grant permission; resolve current native items per hit.

    One Meili request or one native directory page, at most 100 returned items.
    Native mode searches file/folder names here, without entering children.
    """
    deadline = time.monotonic() + 10
    repo_id, q, path, limit = validate(repo_id, q, path, limit)
    # Native offsets page one fixed directory. A global 10k cap would silently
    # hide later entries in large directories despite a valid continuation.
    max_offset = 2 ** 31 - 501 if provider == 'native' else 10000
    if type(offset) is not int or not 0 <= offset <= max_offset or provider not in (None, 'meilisearch', 'native'):
        raise SearchFailure('INVALID_CURSOR', 'Invalid search cursor', 400)
    if not can_read(path):
        raise SearchFailure('PERMISSION_DENIED', 'Permission denied', 403)
    if provider == 'meilisearch' and client is None:
        # A changed provider configuration invalidates an existing cursor too.
        raise SearchFailure('SEARCH_UNAVAILABLE', 'Search index unavailable')
    candidates = None
    native_entries = {}
    if provider != 'native' and client is not None:
        clauses = ['repo_id = ' + json.dumps(repo_id)]
        if path != '/':
            clauses.append('dirs IN ' + json.dumps([path], ensure_ascii=False))
        payload = dict(q=q, offset=offset, limit=limit, filter=' AND '.join(clauses),
            attributesToSearchOn=['name', 'tags'], matchingStrategy='all',
            attributesToRetrieve=['repo_id', 'path', 'tags'], attributesToHighlight=['tags'])
        try:
            response = client._call('POST', '/indexes/%s/search' % INDEX_NAME, payload)
            candidates = response.get('hits')
            if not isinstance(candidates, list) or len(candidates) > limit:
                raise MeilisearchError('invalid candidate page')
        except MeilisearchError:
            # A pagination cursor never silently changes provider/offset meaning.
            if provider == 'meilisearch':
                raise SearchFailure('SEARCH_UNAVAILABLE', 'Search index unavailable') from None
    if candidates is None:
        provider = 'native'
        entries = list_directory(path, offset, 500)
        if time.monotonic() >= deadline or len(entries) > 500:
            raise SearchFailure('SEARCH_UNAVAILABLE', 'Invalid directory page')
        candidates = [dict(repo_id=repo_id, path=posixpath.join(path, e.obj_name))
            for e in entries if (stat.S_ISREG(e.mode) or stat.S_ISDIR(e.mode)) and q.casefold() in e.obj_name.casefold()]
        # The bounded listing already contains these dirents. The HTTP adapter
        # still rechecks the repository head before publishing, so rereading
        # every match adds RPCs without supplying a newer usable snapshot.
        native_entries = {posixpath.join(path, e.obj_name): e for e in entries}
        next_offset = offset + len(entries) if len(entries) == 500 else None
    else:
        provider = 'meilisearch'
        next_offset = offset + len(candidates) if len(candidates) == limit else None
    # Normalize and deduplicate before loading permission inputs. Native pages
    # may contain 500 matches; bounded windows avoid authorizing a whole page
    # when the first result window already fills the requested limit.
    normalized, seen = [], set()
    for hit in candidates:
        if time.monotonic() >= deadline:
            raise SearchFailure('SEARCH_UNAVAILABLE', 'Search time budget exceeded')
        try:
            candidate_path = normalize_path(hit['path'], 'file')
        except Exception:
            raise SearchFailure('SEARCH_UNAVAILABLE', 'Invalid indexed path') from None
        if hit.get('repo_id') != repo_id:
            raise SearchFailure('SEARCH_UNAVAILABLE', 'Invalid indexed library')
        if candidate_path in seen or (path != '/' and not candidate_path.startswith(path + '/')):
            continue
        seen.add(candidate_path)
        normalized.append((hit, candidate_path))
    items = []
    for index, (hit, candidate_path) in enumerate(normalized):
        if time.monotonic() >= deadline:
            raise SearchFailure('SEARCH_UNAVAILABLE', 'Search time budget exceeded')
        if prepare_paths is not None and index % limit == 0:
            prepare_paths([target for _, candidate in normalized[index:index + limit]
                for target in (posixpath.dirname(candidate) or '/', candidate)])
        # Current CE/C existence and current read permission replace index metadata.
        parent = posixpath.dirname(candidate_path) or '/'
        if not can_read(parent) or not can_read(candidate_path):
            continue
        entry = native_entries.get(candidate_path) if provider == 'native' else resolve_item(candidate_path)
        if entry is None:
            continue
        directory = stat.S_ISDIR(entry.mode)
        tags = hit.get('tags') or []
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            raise SearchFailure('SEARCH_UNAVAILABLE', 'Invalid indexed tags')
        items.append(dict(path=candidate_path, name=posixpath.basename(candidate_path),
            type='folder' if directory else 'file', size=entry.size, mtime=entry.mtime,
            tags=tags, matched_tags=_matched_tags((hit.get('_formatted') or {}).get('tags'))))
        if len(items) == limit:
            # Native page truncation resumes after the emitted candidate, not
            # after all 500 entries, so remaining name matches cannot disappear.
            if provider == 'native':
                index = next(i for i, e in enumerate(entries) if posixpath.join(path, e.obj_name) == candidate_path)
                next_offset = offset + index + 1 if index + 1 < len(entries) or len(entries) == 500 else None
            break
    if time.monotonic() >= deadline:
        raise SearchFailure('SEARCH_UNAVAILABLE', 'Search time budget exceeded')
    return dict(data=items, provider=provider, fallback=provider == 'native',
        scope='directory' if provider == 'native' else 'subtree', path=path,
        next_offset=next_offset if next_offset is not None and next_offset <=
            (2 ** 31 - 501 if provider == 'native' else 10000) else None)
