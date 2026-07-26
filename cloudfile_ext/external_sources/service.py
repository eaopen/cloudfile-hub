# -*- coding: utf-8 -*-
"""Gathering the facts the authorisation rule decides on, and reading sources.

The rule itself is cloudfile_ext.external_sources.authz.decide -- pure, and
importable without Django, for the reasons that module states. Everything here
is the part that cannot be pure: group lookups, queries, and the provider call.

Why authorisation is in this layer and not in the provider: a backend answers
"what is at this path", once, for every source type. A backend that also had to
decide who may read is a backend that can leak by forgetting to -- the same
reasoning that keeps repo scoping out of search providers.
"""

import logging

from cloudfile_ext.external_sources.authz import (
    SUBJECT_GROUP, SUBJECT_USER, decide,
)
from cloudfile_ext.external_sources.providers import SourceError

logger = logging.getLogger(__name__)


class NoSuchSource(Exception):
    """No enabled source with that id.

    Raised rather than returning None so that a caller cannot forget to check
    and end up treating "no source" as "no restrictions".
    """


def _user_group_ids(username):
    from seaserv import ccnet_api

    ids = []
    for group in ccnet_api.get_groups(username) or ():
        ids.append(group.id)
    return ids


def get_source(source_id=None, repo_id=None):
    """An enabled source by id or synthetic repo id. Raises NoSuchSource."""
    from cloudfile_ext.external_sources.models import ExternalSource

    qs = ExternalSource.objects.filter(enabled=1)
    if source_id is not None:
        source = qs.filter(id=source_id).first()
    elif repo_id is not None:
        source = qs.filter(repo_id=repo_id).first()
    else:
        raise NoSuchSource('one of source_id or repo_id is required')
    if source is None:
        raise NoSuchSource('no enabled external source for %s' %
                           (source_id if source_id is not None else repo_id))
    return source


def permission_for(username, source, path='/', is_staff=False):
    """The user's permission on `path` in `source`, or None.

    Two stages, and the order matters. First the source's own grants decide the
    native permission (:func:`decide`). Then the registered permission chain
    may narrow it -- which is what makes a directory ACL rule apply to an
    external source's subdirectory with no code here at all, since the source
    carries a synthetic repo_id that cf_dir_acl can be keyed by.

    Deliberately **not** routed through seahub.views.check_folder_permission.
    That asks seafile_api.check_permission_by_path first, and the synthetic
    repo_id names no row in seafile-db, so the native answer is None -- and
    since hooks may only tighten, the result would be pinned to "deny" for
    every user including the ones with a grant. hooks.check_permission is the
    actual contract; check_folder_permission is just one of its callers.
    """
    from cloudfile_ext.external_sources.models import ExternalSourceGrant
    from cloudfile_ext import hooks

    group_ids = [] if is_staff else _user_group_ids(username)

    # Fetch only the rows that can match: this user, or one of their groups.
    # A source shared with a hundred groups should not pull a hundred rows to
    # answer one request.
    from django.db.models import Q
    condition = Q(subject_type=SUBJECT_USER, subject=username)
    if group_ids:
        condition |= Q(subject_type=SUBJECT_GROUP,
                       subject__in=[str(g) for g in group_ids])
    rows = ExternalSourceGrant.objects.filter(
        Q(source_id=source.id) & condition
    ).values_list('subject_type', 'subject', 'permission')

    native = decide(rows, is_staff=is_staff, group_ids=group_ids,
                    enabled=bool(source.enabled))
    if native is None:
        return None

    return hooks.check_permission(username, source.repo_id, path, native)


def backend_for(source):
    """The registered provider for a source's type.

    Raises SourceError when nothing is registered for it -- which happens if a
    source was registered by a build that had a backend this one does not.
    Explicit failure rather than an empty listing, for the reason stated in
    providers.py: an empty answer is indistinguishable from an empty share.
    """
    from cloudfile_ext.registry import registry

    backend = registry.external_sources.get(source.source_type)
    if backend is None:
        raise SourceError('no backend registered for source type %r'
                          % source.source_type)
    return backend


def list_dir(source, path):
    """Entries under `path`, sorted directories-first then by name.

    Sorting is here rather than in the backend because it is presentation: a
    backend should not pay to order a large directory that a scanner is going
    to consume unordered anyway (see providers.Source.list_dir).
    """
    entries = backend_for(source).list_dir(source.root_path, path)
    return sorted(entries, key=lambda e: (not e.is_dir, e.name.lower()))


def serialize_entry(entry, parent_path):
    from cloudfile_ext.external_sources import paths

    parent = paths.normalize_rel_path(parent_path)
    full = entry.name if parent == '/' else '%s/%s' % (parent, entry.name)
    return {
        'name': entry.name,
        'path': '/' + full.lstrip('/'),
        'type': 'dir' if entry.is_dir else 'file',
        'size': entry.size,
        'mtime': entry.mtime,
    }


def serialize_source(source, permission=None):
    info = {
        'id': source.id,
        'repo_id': source.repo_id,
        'name': source.name,
        'source_type': source.source_type,
        'enabled': bool(source.enabled),
        'ctime': source.ctime,
        'mtime': source.mtime,
    }
    if permission is not None:
        info['permission'] = permission
    return info
