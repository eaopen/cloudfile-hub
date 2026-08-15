# -*- coding: utf-8 -*-
"""Meilisearch as a search_files() provider.

Registered under CF_PROVIDER_SEARCH = 'meilisearch'
(cloudfile_ext.search.register). Documents live in a single unified index
(docs/search.md section 5 -- "统一文件索引 + repo_id 过滤", chosen over
SeaSearch's one-index-per-library layout so that a query spanning many
libraries does not have to fan out to many indexes). This module only reads
that index; cloudfile_ext.search.indexer is the only writer.

Not built on cloudfile_ext.external_service.ExternalService: that class signs
a short-lived JWT for CloudFile's own services, and Meilisearch authenticates
with a single static API key instead -- reusing it would mean bending one
convention to fit a shape it was not designed for. This client is deliberately
small: four HTTP calls, no retry-with-backoff, because a slow search backend
should fail a query fast rather than hold a request open.
"""

import json
import logging
import urllib.error
import urllib.request

from cloudfile_ext import search_query

logger = logging.getLogger(__name__)

#: Single index for every library -- see module docstring.
INDEX_NAME = 'cloudfile_files'

#: Attributes pushed to Meilisearch by ensure_index(). The indexer and this
#: query-side module share one definition so they can never drift apart.
#:
#: `creator` (library owner) and `tags` let the advanced filter panel narrow a
#: query server-side; `tags` is also searchable so a tag name can match a file
#: whose name and content do not -- and the hit reports which tags matched so
#: the UI never presents a tag hit as a name hit.
FILTERABLE_ATTRIBUTES = ['repo_id', 'path', 'object_type', 'extension', 'mtime', 'size', 'creator', 'tags']
SORTABLE_ATTRIBUTES = ['mtime', 'size', 'name']
SEARCHABLE_ATTRIBUTES = ['name', 'path', 'content', 'tags']

#: Translation from cloudfile_ext.search_query operators to Meilisearch filter
#: syntax. Only entries here may appear in supported_filter_ops below --
#: declaring one without the other would let check_supported() wave a filter
#: through that this module cannot actually honour.
_OP_TEMPLATES = {
    search_query.EQ: '{field} = {value}',
    search_query.NE: '{field} != {value}',
    search_query.IN: '{field} IN {value}',
    search_query.EXISTS: '{field} EXISTS',
}


class MeilisearchError(Exception):
    """A Meilisearch call failed."""


def _quote(value):
    # ensure_ascii=False: Meilisearch's filter grammar expects literal UTF-8
    # inside the quotes, not JSON's \uXXXX escapes -- and paths/tags here are
    # routinely non-ASCII (this is a Chinese enterprise product). The JSON
    # body payloads elsewhere in this module go through a real JSON parser on
    # the other end and are unaffected either way.
    return json.dumps(value, ensure_ascii=False)


def _filter_expr(f):
    template = _OP_TEMPLATES.get(f.op)
    if template is None:
        # search_query.check_supported() already refuses this before the
        # provider is called; this is a second, defensive line in case
        # supported_filter_ops and _OP_TEMPLATES ever drift apart.
        raise search_query.UnsupportedFilter(
            'meilisearch backend cannot translate operator %r' % f.op)
    if f.op == search_query.EXISTS:
        return template.format(field=f.field)
    if f.op == search_query.IN:
        return template.format(field=f.field,
                              value=json.dumps(list(f.value), ensure_ascii=False))
    return template.format(field=f.field, value=_quote(f.value))


def _clean_highlight(text):
    """Strip Meilisearch's default ``<em>`` highlight markers."""
    return text.replace('<em>', '').replace('</em>', '')


def _matched_tags(formatted_tags):
    """Tag names whose stored form carries a highlight marker.

    ``attributesToHighlight=['tags']`` makes Meilisearch wrap the matched term
    inside a tag value with ``<em>``. A highlighted tag therefore means "this
    hit matched via the tag, not the name", which is exactly the signal the UI
    needs to show a 'matched tag' indicator instead of implying a name match.
    """
    if not formatted_tags:
        return []
    return [_clean_highlight(t) for t in formatted_tags if '<em>' in t]


class MeilisearchClient(object):

    def __init__(self, url, api_key='', timeout=5):
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self):
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = 'Bearer %s' % self.api_key
        return headers

    def _call(self, method, path, payload=None, ignore_status=()):
        url = '%s%s' % (self.url, path)
        body = json.dumps(payload).encode('utf-8') if payload is not None else None
        req = urllib.request.Request(url, data=body, method=method,
                                     headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode('utf-8')
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            if exc.code in ignore_status:
                return {}
            raise MeilisearchError('%s %s: HTTP %s' % (method, path, exc.code))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MeilisearchError('%s %s: %s' % (method, path, exc))

    def ensure_index(self):
        """Idempotent: create the index if missing, push its settings.

        Meilisearch has no create-if-missing verb, so a 4xx from the create
        call on every run after the first is expected, not an error -- it
        means "already exists". A failure pushing *settings* is not ignored:
        an index with the wrong filterable attributes fails every filtered
        query at read time instead, in a way this call is the last chance to
        catch.
        """
        self._call('POST', '/indexes', {'uid': INDEX_NAME, 'primaryKey': 'id'},
                   ignore_status=(400,))
        self._call('PATCH', '/indexes/%s/settings' % INDEX_NAME, {
            'filterableAttributes': FILTERABLE_ATTRIBUTES,
            'sortableAttributes': SORTABLE_ATTRIBUTES,
            'searchableAttributes': SEARCHABLE_ATTRIBUTES,
        })

    def upsert_documents(self, documents):
        if not documents:
            return
        self._call('PUT', '/indexes/%s/documents' % INDEX_NAME, documents)

    def delete_documents(self, document_ids):
        if not document_ids:
            return
        self._call('POST', '/indexes/%s/documents/delete-batch' % INDEX_NAME,
                   list(document_ids))

    def delete_by_repo(self, repo_id):
        self._call('POST', '/indexes/%s/documents/delete' % INDEX_NAME,
                   {'filter': 'repo_id = %s' % _quote(repo_id)})

    def search(self, query, filter_expr, offset, limit, filename_only=False):
        payload = {'q': query or '', 'offset': offset, 'limit': limit,
                   'attributesToHighlight': ['tags']}
        if filter_expr:
            payload['filter'] = filter_expr
        if filename_only:
            payload['attributesToSearchOn'] = ['name']
        return self._call('POST', '/indexes/%s/search' % INDEX_NAME, payload)


def client_from_settings():
    from django.conf import settings
    return MeilisearchClient(
        url=getattr(settings, 'CF_MEILISEARCH_URL', 'http://meilisearch:7700'),
        api_key=getattr(settings, 'CF_MEILISEARCH_API_KEY', ''),
        timeout=getattr(settings, 'CF_MEILISEARCH_TIMEOUT', 5),
    )


def _obj_desc_clauses(obj_desc):
    """Best-effort translation of Seahub's file-intrinsic filter dict.

    obj_desc is upstream's own vocabulary (seahub.api2.views.Search.get()):
    obj_type, suffixes, time_range, size_range. It is orthogonal to
    cloudfile_ext.search_query (user-defined attributes/tags) -- see
    search_query's module docstring -- so it is translated here directly
    rather than through that vocabulary.
    """
    if not obj_desc:
        return []
    clauses = []
    obj_type = obj_desc.get('obj_type')
    if obj_type:
        clauses.append('object_type = %s' % _quote(obj_type))
    suffixes = obj_desc.get('suffixes')
    if suffixes:
        clauses.append('extension IN %s' % json.dumps(list(suffixes), ensure_ascii=False))
    time_from, time_to = obj_desc.get('time_range') or (None, None)
    if time_from is not None:
        clauses.append('mtime >= %d' % time_from)
    if time_to is not None:
        clauses.append('mtime <= %d' % time_to)
    size_from, size_to = obj_desc.get('size_range') or (None, None)
    if size_from is not None:
        clauses.append('size >= %d' % size_from)
    if size_to is not None:
        clauses.append('size <= %d' % size_to)
    return clauses


class MeilisearchProvider(object):
    """search_files() contract -- see cloudfile_ext.registry.register_search_provider."""

    #: Declared per cloudfile-docker/docs/EXTENSION-POINTS.md section six's
    #: example. Combined search (feature 41) is not wired up yet -- nothing
    #: feeds cloudfile_ext.search_query predicates today -- but declaring the
    #: operators this backend can actually translate now means that feature
    #: only has to add the metadata side later, not come back here.
    supported_filter_ops = frozenset(_OP_TEMPLATES)

    def __init__(self, client=None):
        self._client = client

    def _get_client(self):
        return self._client or client_from_settings()

    def search_files(self, repos_map, search_path, keyword, obj_desc, start, size,
                     org_id=None, search_filename_only=False, filters=None):
        repo_ids = list(repos_map.keys())
        if not repo_ids:
            return [], 0

        clauses = ['repo_id IN %s' % json.dumps(repo_ids, ensure_ascii=False)]
        if search_path:
            # Only ever passed together with a single-repo repos_map (see
            # seahub.search.utils.search_files) -- a "search within this
            # folder" narrowing, not a permission boundary, so best-effort is
            # fine here.
            clauses.append('path STARTS WITH %s' % _quote(search_path.rstrip('/') + '/'))
        clauses.extend(_obj_desc_clauses(obj_desc))
        for f in (filters or []):
            clauses.append(_filter_expr(f))

        client = self._get_client()
        try:
            resp = client.search(keyword, ' AND '.join(clauses), start, size,
                                 filename_only=search_filename_only)
        except MeilisearchError:
            logger.exception('meilisearch query failed; returning no results')
            return [], 0

        hits = []
        for doc in resp.get('hits', []):
            formatted = doc.get('_formatted') or {}
            hits.append({
                'repo_id': doc.get('repo_id'),
                'fullpath': doc.get('path'),
                'name': doc.get('name'),
                'size': doc.get('size'),
                'tags': doc.get('tags') or [],
                'matched_tags': _matched_tags(formatted.get('tags')),
            })
        total = resp.get('estimatedTotalHits', len(hits))
        return hits, total
