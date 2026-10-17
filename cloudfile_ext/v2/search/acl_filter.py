"""Meilisearch pre-filter from the same V2 decisions as directory browsing.

It only narrows candidates: every returned hit is still decided by Authority,
so an imprecise filter can cost results or extra candidates, never access.
Uses only `path` and `dirs` (exact ancestors, excluding "/" and the object),
which the existing index already filters on; nothing is re-indexed.

A decision depends only on which rule paths are ancestors of the evaluated
directory (a file's parent), so every object whose deepest rule-path ancestor
in `dirs` is B shares one region. Anything readable in that region (B's
files, or a deeper non-rule directory) requires B itself readable, since its
ancestor chain passes through B. A region is therefore kept exactly when B is
readable. Without a parent field this over-includes the region when only B's
own level is readable (a non-inherited grant), never the reverse. A rule path
directory document lives in its parent's region and gets an exact clause.
"""
import json

from cloudfile_ext.v2.acl_policy import within

MAX_RULE_PATHS = 256
MAX_FILTER_BYTES = 32768


class FilterUnavailable(Exception):
    """Over budget: search falls back to per-hit authorization only."""


class _Nothing:
    def __repr__(self):
        return 'NOTHING'


# Nothing in the library is readable, so no candidate query is needed.
NOTHING = _Nothing()


def quote(value):
    return json.dumps(value, ensure_ascii=False)


def _list(values):
    return '[' + ', '.join(quote(value) for value in values) + ']'


def _children(anchor, paths):
    """Rule paths directly below anchor in the rule-path forest."""
    below = [p for p in paths if p != anchor and within(p, anchor)]
    return sorted(p for p in below if not any(q != p and within(p, q) for q in below))


def build(rule_paths, readable):
    """rule_paths: paths of every rule row matching this principal in the library.

    readable(directory) -> bool is the current Authority decision. Returns None
    when nothing is excluded, NOTHING when nothing is readable, else a
    parenthesized filter expression.
    """
    paths = set(rule_paths)
    if len(paths) > MAX_RULE_PATHS:
        raise FilterUnavailable('too many rule paths')
    clauses, exact = [], []
    for anchor in ['/'] + sorted(paths - {'/'}):
        if not readable(anchor):
            continue
        if anchor != '/':
            exact.append(anchor)
        parts = [] if anchor == '/' else ['dirs IN ' + _list([anchor])]
        children = _children(anchor, paths)
        if children:
            parts.append('NOT dirs IN ' + _list(children))
        if not parts:
            return None
        clauses.append(' AND '.join(parts) if len(parts) == 1 else '(' + ' AND '.join(parts) + ')')
    if exact:
        clauses.append('path IN ' + _list(exact))
    if not clauses:
        return NOTHING
    expression = '(' + ' OR '.join(clauses) + ')'
    if len(expression.encode('utf-8')) > MAX_FILTER_BYTES:
        raise FilterUnavailable('filter too large')
    return expression
