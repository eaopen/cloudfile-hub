"""Bounded HTTP access to the existing Meilisearch document format.

The index is derived data, not a resource or authorization database.  This
module deliberately has no Seahub imports, table creation, migration or worker.
"""
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class SearchUnavailable(RuntimeError):
    pass


class SearchWindowExceeded(SearchUnavailable):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def normalize_path(value):
    if not isinstance(value, str) or not value.startswith('/') or (
            value != '/' and value.endswith('/')) or '//' in value or (
            any(segment in ('.', '..') for segment in value.split('/'))):
        raise ValueError('invalid search path')
    try:
        if len(value.encode('utf-8')) > 4096 or '\x00' in value:
            raise ValueError('invalid search path')
    except UnicodeError:
        raise ValueError('invalid search path') from None
    return value


def exact_subtree(candidate, root):
    return root == '/' or candidate.startswith(root + '/')


def checked_reference(hit, repo_id, root):
    """Only path, repo and expected kind are accepted from the untrusted index."""
    if not isinstance(hit, dict) or hit.get('repo_id') != repo_id:
        raise SearchUnavailable('index repository mismatch')
    try:
        path = normalize_path(hit.get('path'))
    except ValueError:
        raise SearchUnavailable('invalid indexed path') from None
    if path == '/' or not exact_subtree(path, root):
        raise SearchUnavailable('indexed path outside scope')
    kind = hit.get('object_type')
    if kind == 'folder':
        kind = 'dir'
    if kind not in ('file', 'dir'):
        raise SearchUnavailable('invalid indexed kind')
    return dict(repo_id=repo_id, path=path, kind=kind)


def search_filters(*, kind=None, extension=None, tag=None):
    """Validate optional indexed fields without interpreting client filter SQL."""
    if kind not in (None, 'file', 'dir'):
        raise ValueError('invalid search object kind')
    if extension is not None:
        if not isinstance(extension, str) or not re.fullmatch(r'[.]?[A-Za-z0-9]{1,16}', extension):
            raise ValueError('invalid file extension')
        extension = extension.lstrip('.').lower()
    if tag is not None:
        if (not isinstance(tag, str) or not tag or tag != tag.strip()
                or len(tag) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in tag)):
            raise ValueError('invalid native tag label')
        try:
            tag.encode('utf-8')
        except UnicodeError:
            raise ValueError('invalid native tag label') from None
    if kind == 'dir' and extension:
        raise ValueError('directories have no file extension')
    return kind, extension, tag


class ExistingMeiliIndex:
    """Adapter to the existing cloudfile_files document format."""

    def __init__(self, endpoint, api_key='', index='cloudfile_files', timeout=5):
        parsed = urlsplit(endpoint or '')
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or
                parsed.username or parsed.password or parsed.query or
                parsed.fragment or parsed.path not in ('', '/')):
            raise ValueError('trusted Meilisearch endpoint required')
        if (not isinstance(index, str) or not index or len(index) > 128 or
                any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in index)):
            raise ValueError('invalid Meilisearch index')
        self.endpoint = endpoint.rstrip('/')
        self.index_path = '/indexes/' + index
        self.api_key = api_key
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())
        # Only memoized inside this request-scoped client, never persisted.
        self._pagination_cap = None

    def call(self, method, path, payload=None):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
                   'Accept-Encoding': 'identity'}
        if self.api_key:
            headers['Authorization'] = 'Bearer ' + self.api_key
        request = Request(self.endpoint + path,
                          data=json.dumps(payload, ensure_ascii=False).encode('utf-8') if payload is not None else None,
                          method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if response.status not in (200, 202) or response.headers.get_content_type() != 'application/json':
                    raise SearchUnavailable('index response invalid')
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise SearchUnavailable('index response too large')
                return json.loads(raw.decode('utf-8'))
        except (HTTPError, URLError, OSError, UnicodeError, ValueError, TypeError) as exc:
            raise SearchUnavailable('Meilisearch unavailable') from exc

    def page(self, repo_id, root, query, offset, limit, *, kind=None, extension=None, tag=None):
        if (not isinstance(repo_id, str) or not isinstance(query, str) or not query or
                type(offset) is not int or offset < 0 or type(limit) is not int or
                not 1 <= limit <= 101):
            raise ValueError('invalid candidate query')
        root = normalize_path(root)
        kind, extension, tag = search_filters(kind=kind, extension=extension, tag=tag)
        filters = ['repo_id = ' + json.dumps(repo_id)]
        if root != '/':
            filters.append('dirs IN ' + json.dumps([root], ensure_ascii=False))
        if kind == 'file':
            filters.append('object_type = "file"')
        elif kind == 'dir':
            filters.append('object_type IN ["dir","folder"]')
        if extension is not None:
            filters.append('extension = ' + json.dumps(extension))
        if tag is not None:
            filters.append('tags = ' + json.dumps(tag, ensure_ascii=False))
        payload = dict(q=query, offset=offset, limit=limit, filter=' AND '.join(filters),
                       matchingStrategy='all', attributesToSearchOn=['name', 'tags'],
                       attributesToRetrieve=['repo_id', 'path', 'name', 'object_type', 'tags'],
                       attributesToHighlight=['name', 'tags'])
        try:
            data = self.call('POST', self.index_path + '/search', payload)
            hits = data.get('hits') if isinstance(data, dict) else None
            if not isinstance(hits, list) or len(hits) > limit:
                raise SearchUnavailable('invalid candidate page')
            # The existing index has a finite candidate window. Never silently
            # describe its cap as the end of all authorized matches.
            if self._pagination_cap is None:
                cap = self.call('GET', self.index_path + '/settings/pagination')['maxTotalHits']
                if type(cap) is not int or cap < 1:
                    raise SearchUnavailable('invalid index pagination settings')
                self._pagination_cap = cap
            cap = self._pagination_cap
            if data.get('estimatedTotalHits', 0) >= cap and offset + len(hits) >= cap:
                raise SearchWindowExceeded('narrow the search scope or query')
            items = []
            for hit in hits:
                reference = checked_reference(hit, repo_id, root)
                if (kind is not None and reference['kind'] != kind) or (
                        extension is not None and
                        (reference['kind'] != 'file' or
                         reference['path'].rsplit('/', 1)[-1].rsplit('.', 1)[-1].lower() != extension)):
                    raise SearchUnavailable('indexed result outside requested filters')
                tags = hit.get('tags') or []
                if not isinstance(tags, list) or any(not isinstance(t, str) or len(t) > 255 for t in tags):
                    raise SearchUnavailable('invalid indexed tags')
                if tag is not None and tag not in tags:
                    raise SearchUnavailable('indexed tag filter not satisfied')
                formatted = hit.get('_formatted') or {}
                if not isinstance(formatted, dict):
                    raise SearchUnavailable('invalid highlighted tags')
                highlighted = formatted.get('tags') or []
                matched = []
                if isinstance(highlighted, list):
                    for word in highlighted:
                        if isinstance(word, str) and '<em>' in word:
                            matched.append(word.replace('<em>', '').replace('</em>', ''))
                text_match = isinstance(formatted.get('name'), str) and '<em>' in formatted['name']
                items.append(dict(**reference, text_match=text_match, matched_tags=matched))
            return items
        except (HTTPError, URLError, OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
            raise SearchUnavailable('existing Meilisearch index unavailable') from exc
