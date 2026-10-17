"""Current V2 authority for the existing derived index.

Candidates are narrowed by a Meilisearch filter built from the same Authority
decisions as directory browsing (acl_filter). Every returned hit is decided
again by that Authority and checked against the current native tree, so the
index and its filter are never an authorization source.
"""
from dataclasses import astuple
import hashlib
import json
import stat

from seaserv import seafile_api

from cloudfile_ext.v2.acl_runtime import Authority

from . import acl_filter
from .client import SearchUnavailable


class AccessDenied(Exception):
    pass


def native_tags(repo_id, references):
    """Current native tag names for these authorized search hits, not stale index tags."""
    from cloudfile_ext.v2.tag_reads import read
    tags = read(repo_id, [(ref['path'], ref['kind']) for ref in references])
    return {path: sorted({tag['tag_name'] for tag in tags[(path, kind)]})
            for path, kind in tags}


class SearchAuthority:
    def __init__(self, username, repo_id, root, *, authority=None):
        self.username, self.repo_id, self.root = username, repo_id, root
        repo = seafile_api.get_repo(repo_id)
        if repo is None:
            raise AccessDenied()
        # Virtual and encrypted repositories need explicit index/path mapping.
        if repo.is_virtual or repo.encrypted:
            raise SearchUnavailable('repository search mapping unavailable')
        try:
            self.authority = Authority(username) if authority is None else authority
        except PermissionError:
            raise AccessDenied() from None  # inactive native account
        self.snapshot = self.read_snapshot(self.authority, repo)
        self.version = hashlib.sha256(json.dumps(self.snapshot, sort_keys=True).encode()).hexdigest()
        self.filter = self.candidate_filter()

    def read_snapshot(self, authority, repo):
        """Every input of this library's decisions; binds cursors and the filter."""
        try:
            if not authority.effective(self.repo_id, self.root).can_read:
                raise AccessDenied()
        except PermissionError:
            raise AccessDenied() from None
        view = authority.library_view(self.repo_id)
        principal = authority.principal
        return dict(head=repo.head_cmmt_id, native=view['native'], status=view['status'],
                    principal=[principal.provider, principal.uid, principal.active, principal.ready,
                               sorted(list(group) for group in principal.groups)],
                    rules=None if view['rules'] is None else sorted(list(astuple(rule)) for rule in view['rules']))

    def candidate_filter(self):
        rules = self.snapshot['rules']
        if rules is None:
            return None  # Over-budget library: per-hit authorization only.
        try:
            return acl_filter.build({rule[1] for rule in rules},
                                    lambda path: self.authority.effective(self.repo_id, path).can_read)
        except acl_filter.FilterUnavailable:
            return None

    def resolve(self, references, authority=None):
        authority = self.authority if authority is None else authority
        # An index candidate is never a tag-read authority. Authorize and
        # verify the current native object BEFORE selecting its tag bindings.
        entries, visible = [], []
        for ref in references:
            path, kind = ref['path'], ref['kind']
            if not authority.effective(self.repo_id, path, kind).can_read:
                entries.append(None)
                continue
            entry = seafile_api.get_dirent_by_path(self.repo_id, path)
            if entry is None or (stat.S_ISDIR(entry.mode) if kind == 'dir' else stat.S_ISREG(entry.mode)) is False:
                entries.append(None)
                continue
            entries.append(entry)
            visible.append(ref)
        # Failure to read tags for valid hits remains an error, not an empty tag
        # set. Unauthorized or stale hits cause no tag query at all.
        tags = native_tags(self.repo_id, visible) if visible else {}
        result = []
        for ref, entry in zip(references, entries):
            if entry is None:
                result.append(None)
                continue
            path, kind = ref['path'], ref['kind']
            current = tags[path]
            matched = [t for t in ref.get('matched_tags', []) if t in current]
            if not ref.get('text_match', True) and not matched:
                result.append(None)
                continue
            result.append(dict(repo_id=self.repo_id, path=path, kind=kind,
                               size=entry.size if kind == 'file' else 0, mtime=entry.mtime,
                               tags=current, matched_tags=matched))
        return result

    def assert_current(self, references):
        repo = seafile_api.get_repo(self.repo_id)
        if repo is None:
            raise AccessDenied()
        # Revalidate native account and current UID/group projection; reusing
        # the previous principal here would miss mid-request identity changes.
        try:
            fresh = Authority(self.username)
        except PermissionError:
            raise AccessDenied() from None
        if self.read_snapshot(fresh, repo) != self.snapshot:
            raise SearchUnavailable('library or authorization changed')
        # With every decision input unchanged the decisions are too, except in
        # an over-budget library, whose per-directory candidates are not bound.
        if self.snapshot['rules'] is None and self.resolve(references, fresh) != references:
            raise SearchUnavailable('object authorization or metadata changed')
