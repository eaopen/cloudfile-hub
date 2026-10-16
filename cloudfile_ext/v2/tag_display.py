"""Read current native CE tags only for entries already authorized on this page.

RepoTags are standard editable labels. Legacy free Tags are displayed read-only;
neither type of tag participates in ACL. No snapshot, signal or cache state.
"""
import posixpath

from .tag_reads import read as read_tags

MAX_PAGE = 100


def read_page(repo_id, parent, entries):
    """Return tags for one authorized directory page, using batched native queries."""
    return read_tags(repo_id, entries)


def tags_for_entries(repo_id, parent, entries):
    if not entries:
        return {}
    if len(entries) > MAX_PAGE or any(
            kind not in ('file', 'dir') or not isinstance(path, str) or
            posixpath.dirname(path) != parent or posixpath.basename(path) in ('', '.', '..')
            for path, kind in entries):
        raise ValueError('invalid tag page references')
    return read_page(repo_id, parent, entries)
