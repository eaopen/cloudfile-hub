# -*- coding: utf-8 -*-
"""Built-in tag/file query backend backed by Seahub's own tables.

Why this exists
---------------
Tag search used to require an external index: ``api2/search/?tags=...`` turns
the parameter into a structured ``tags IN (...)`` predicate, and only a
CloudFile *provider* can honour it. With no provider configured the predicate is
refused (``UnsupportedFilter``) and Seahub's bare ``except`` renders an empty
result page -- so a CE deployment without Elasticsearch, or one that simply
never selected ``CF_PROVIDER_SEARCH``, shows "nothing matched" for a tag that
does exist. That is a wrong answer, not a missing feature.

This backend answers the predicates the tag tables can answer *by themselves*:

* ``tags``    -- Seahub stores the tag<->path mapping (v2 ``file_tags`` and
                 legacy ``tags_filetag``), so "which files/dirs carry tag X" is
                 a join, no index needed. Both stores are consulted, so system
                 tags (v2) and user tags (legacy, which also cover folders) are
                 both searchable.
* ``creator`` -- the library owner is a property of the repository.

It deliberately does **not** pretend to be a full-text index: content search
still needs Elasticsearch/Meilisearch. ``keyword`` narrows the tag-matched
candidates by name/path substring, which is the honest degradation and is
documented as such (``docs/search.md``).

That asymmetry is why ``hooks.search_files`` only routes *filtered* queries here
and leaves plain keyword queries to the native path: ``tags_fileuuidmap`` rows
only exist for objects that have been tagged at least once, so a keyword-only SQL
scan would silently miss most of a library.

Django-free at import time (like the rest of ``cloudfile_ext/search``): the
Django-backed repository is imported lazily inside ``_get_repository``, and tests
inject a fake repository.
"""

from cloudfile_ext import search_query

#: Operators this backend can honour. ``tags IN (a, b)`` / ``tags = a`` are the
#: mapping joins; ``tags CONTAINS a`` is a substring match on the tag name
#: (useful for "every UG version" style queries). Anything else -- metadata
#: attributes in particular -- is refused rather than ignored, so callers never
#: receive results that silently dropped a predicate.
SUPPORTED_OPS = frozenset((search_query.EQ, search_query.IN, search_query.CONTAINS))

FIELD_TAGS = 'tags'
FIELD_CREATOR = 'creator'


def _values(filter_):
    """Predicate values as a list, for both scalar and sequence operators."""
    if filter_.value is None:
        return []
    if isinstance(filter_.value, (list, tuple, set, frozenset)):
        return [v for v in filter_.value if v]
    return [filter_.value]


def tag_predicates(filters):
    """``[(op, [names])]`` for every ``tags`` predicate, in declaration order."""
    out = []
    for filter_ in filters or []:
        if filter_.field == FIELD_TAGS:
            out.append((filter_.op, _values(filter_)))
    return out


def creator_predicates(filters):
    """``[(op, [emails])]`` for every ``creator`` predicate."""
    out = []
    for filter_ in filters or []:
        if filter_.field == FIELD_CREATOR:
            out.append((filter_.op, _values(filter_)))
    return out


def tag_names(filters):
    """All tag names any predicate asks for (deduplicated, order kept)."""
    names = []
    for _, values in tag_predicates(filters):
        for name in values:
            if name not in names:
                names.append(name)
    return names


def matches_tag_predicates(row_tags, filters):
    """Whether one object's tag names satisfy every ``tags`` predicate.

    ``IN``/``EQ`` are exact; ``CONTAINS`` is a substring test -- each declared
    operator has to mean for this backend what it means for an indexed one.
    """
    for op, values in tag_predicates(filters):
        if not values:
            continue
        if op == search_query.CONTAINS:
            if not any(v in tag for tag in row_tags for v in values):
                return False
        elif op == search_query.EQ:
            if values[0] not in row_tags:
                return False
        else:  # IN
            if not any(v in row_tags for v in values):
                return False
    return True


def matched_tag_names(row_tags, filters):
    """The subset of ``row_tags`` the predicates actually matched.

    Reported back as ``matched_tags`` so the UI can show why a hit was returned
    -- the same field the indexed backend fills from its highlights.
    """
    matched = []
    for op, values in tag_predicates(filters):
        for tag in row_tags:
            if tag in matched:
                continue
            if op == search_query.CONTAINS:
                if any(v in tag for v in values):
                    matched.append(tag)
            elif op == search_query.EQ:
                if values and values[0] == tag:
                    matched.append(tag)
            else:  # IN
                if tag in values:
                    matched.append(tag)
    return matched


def matches_creator(owner, filters):
    """Whether a repository owner satisfies every ``creator`` predicate."""
    for op, values in creator_predicates(filters):
        if not values:
            continue
        if op == search_query.CONTAINS:
            if not any(v in (owner or '') for v in values):
                return False
        elif op == search_query.EQ:
            if (owner or '') != values[0]:
                return False
        else:  # IN
            if (owner or '') not in values:
                return False
    return True


def extension_of(name):
    return name.rsplit('.', 1)[-1].lower() if '.' in name else ''


def matches_keyword(row, keyword, filename_only=False):
    """Name/path substring match -- the degradation for ``keyword``."""
    if not keyword:
        return True
    needle = keyword.lower()
    if needle in (row.get('name') or '').lower():
        return True
    if filename_only:
        return False
    return needle in (row.get('path') or '').lower()


def matches_search_path(row, search_path):
    """Narrow to a folder; ``search_path`` is best-effort, not a boundary."""
    if not search_path or search_path == '/':
        return True
    prefix = search_path.rstrip('/')
    path = row.get('path') or ''
    return path == prefix or path.startswith(prefix + '/')


def matches_obj_desc(row, obj_desc):
    """Apply the file-intrinsic conditions the tag tables can answer.

    ``suffixes``/``obj_type`` come from the name and the ``is_dir`` flag alone.
    ``size_range``/``time_range`` need the dirent: the repository fills it in only
    when asked (``needs_dirents``), and when it is absent the condition cannot be
    evaluated -- guessing would be worse, so the caller is told through
    ``UnsupportedFilter`` instead.

    Returns ``(keep, missing_data)``.
    """
    obj_desc = obj_desc or {}
    obj_type = obj_desc.get('obj_type')
    if obj_type == 'file' and row.get('is_dir'):
        return True, False
    if obj_type == 'dir' and not row.get('is_dir'):
        return True, False
    suffixes = obj_desc.get('suffixes')
    if suffixes:
        wanted = {str(s).lower().lstrip('.') for s in suffixes}
        if row.get('is_dir') or extension_of(row.get('name') or '') not in wanted:
            return True, False
    size_from, size_to = obj_desc.get('size_range') or (None, None)
    if size_from is not None or size_to is not None:
        if row.get('size') is None:
            return False, True
        if size_from is not None and row['size'] < size_from:
            return True, False
        if size_to is not None and row['size'] > size_to:
            return True, False
    time_from, time_to = obj_desc.get('time_range') or (None, None)
    if time_from is not None or time_to is not None:
        if row.get('mtime') is None:
            return False, True
        if time_from is not None and row['mtime'] < time_from:
            return True, False
        if time_to is not None and row['mtime'] > time_to:
            return True, False
    return True, False


def needs_dirents(obj_desc):
    """Whether ``obj_desc`` carries conditions the tag tables cannot answer."""
    obj_desc = obj_desc or {}
    if obj_desc.get('size_range') not in (None, (None, None)):
        return True
    if obj_desc.get('time_range') not in (None, (None, None)):
        return True
    return False


class DbTagsProvider(object):
    """``search_files()`` contract -- see ``registry.register_search_provider``."""

    supported_filter_ops = SUPPORTED_OPS

    def __init__(self, repository=None):
        self._repository = repository

    def _get_repository(self):
        if self._repository is None:
            from cloudfile_ext.search.backends.django_tag_repository import (
                DjangoTagRepository,
            )
            self._repository = DjangoTagRepository()
        return self._repository

    def search_files(self, repos_map, search_path, keyword, obj_desc, start, size,
                     org_id=None, search_filename_only=False, filters=None):
        repo_ids = list((repos_map or {}).keys())
        if not repo_ids:
            return [], 0

        filters = search_query.parse(filters or [])
        repository = self._get_repository()
        # Reading the dirents up front is only worth a round trip when a
        # size/time condition actually needs them.
        rows = repository.find_rows(repo_ids, tag_names(filters),
                                    with_dirents=needs_dirents(obj_desc))

        owner_of = {
            repo_id: getattr(repo, 'owner', None)
            for repo_id, repo in (repos_map or {}).items()
        }

        matched = []
        for row in rows:
            if not matches_tag_predicates(row.get('tags') or [], filters):
                continue
            if not matches_creator(owner_of.get(row.get('repo_id')), filters):
                continue
            if not matches_search_path(row, search_path):
                continue
            if not matches_keyword(row, keyword, search_filename_only):
                continue
            keep, missing = matches_obj_desc(row, obj_desc)
            if missing:
                raise search_query.UnsupportedFilter(
                    'the built-in tag backend cannot evaluate size_range/'
                    'time_range without an index provider; select '
                    'CF_PROVIDER_SEARCH=meilisearch for that')
            if keep:
                matched.append(row)

        # Deterministic order so paging is stable across requests.
        matched.sort(key=lambda r: ((r.get('path') or ''), r.get('name') or ''))
        total = len(matched)
        page = matched[start:start + size] if size else matched[start:]

        hits = []
        for row in page:
            row_tags = row.get('tags') or []
            hits.append({
                'repo_id': row.get('repo_id'),
                'fullpath': row.get('path'),
                'name': row.get('name'),
                'size': row.get('size'),
                'tags': row_tags,
                'matched_tags': matched_tag_names(row_tags, filters),
            })
        return hits, total
