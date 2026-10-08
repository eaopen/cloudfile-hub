# Copyright (c) 2012-2016 Seafile Ltd.
# -*- coding: utf-8 -*-
import logging

from django.db import IntegrityError
from django.db.models import Q

from seaserv import seafile_api

from seahub.base.models import UserStarredFiles
from seahub.utils import normalize_file_path, normalize_dir_path
from cloudfile_ext.favorites.identity import pick_obj_id, should_backfill
from cloudfile_ext.favorites.lookup import LookupBudget, lookup_content_hint

logger = logging.getLogger(__name__)


def locate_obj_id(repo_id, obj_id, root='/', guard=512, budget=None):
    """Return a bounded, unambiguous content hint for diagnostic callers only.

    Favorites lists must never rebind from this hint: equal content is not
    proof of a move. Callers can share a budget across multiple lookups.
    """
    result = lookup_content_hint(seafile_api.list_dir_by_path, repo_id, obj_id,
                                 root=root, max_depth=guard,
                                 budget=budget or LookupBudget())
    return result.path if result.status == 'unique' else None


def is_favorites_id_enabled():
    """Whether favorites store a content-id hint alongside their path identity.

    Kept lazy so this module stays importable before Django settings are
    finalised, and so turning the switch off restores native CE behaviour.
    """
    try:
        from cloudfile_ext.features import is_enabled
        return is_enabled('CF_ENABLE_FAVORITES_ID')
    except Exception:
        return False


def resolve_obj_id(repo_id, path):
    """Resolve the object id (file obj_id first, then directory id) at path.

    Returns None when the path resolves to neither, so callers can fall back
    to the native path-keyed behaviour instead of treating the item as gone.
    """
    try:
        file_id = seafile_api.get_file_id_by_path(repo_id, path)
        dir_id = None if file_id else seafile_api.get_dir_id_by_path(repo_id, path)
        return pick_obj_id(file_id, dir_id)
    except Exception as e:
        logger.warning('resolve starred obj_id failed for %s %s: %s',
                       repo_id, path, e)
        return None


def backfill_row_obj_id(row):
    """Fill an auxiliary content-id hint from the stored repo_id + path.

    Lossless by design: it only *adds* the id and never deletes a row whose
    path no longer resolves. Returns True when the row was changed.
    """
    if not is_favorites_id_enabled():
        return False
    if row.obj_id:
        return False
    obj_id = resolve_obj_id(row.repo_id, row.path)
    if not should_backfill(row.obj_id, obj_id):
        return False
    row.obj_id = obj_id
    try:
        row.save()
    except Exception as e:
        logger.warning('backfill starred obj_id failed for %s: %s', row.path, e)
        return False
    return True


def star_file(email, repo_id, path, is_dir, org_id=-1):
    obj_id = None
    if is_favorites_id_enabled():
        obj_id = resolve_obj_id(repo_id, path)

    if is_favorites_id_enabled():
        # The path relationship survives content edits; equal content at another
        # path/repo must never overwrite it. obj_id is metadata, not identity.
        paths = [normalize_file_path(path), normalize_dir_path(path)]
        existing = UserStarredFiles.objects.filter(
            email=email, org_id=org_id, repo_id=repo_id, path__in=paths).order_by('pk').first()
        if existing is not None:
            existing.is_dir = is_dir
            if obj_id:
                existing.obj_id = obj_id
            existing.save()
            return
        try:
            UserStarredFiles.objects.create(email=email, org_id=org_id,
                                            repo_id=repo_id, path=path,
                                            is_dir=is_dir, obj_id=obj_id)
        except IntegrityError as e:
            logger.warning(e)
        return

    # Native path-keyed behaviour (switch off, or the path did not resolve).
    if is_file_starred(email, repo_id, path, org_id):
        return

    try:
        UserStarredFiles.objects.create(email=email,
                                        org_id=org_id,
                                        repo_id=repo_id,
                                        path=path,
                                        is_dir=is_dir,
                                        obj_id=None)
    except IntegrityError as e:
        logger.warning(e)


def unstar_file(email, repo_id, path, org_id=-1):
    # Removal targets the current user's exact relationship even after deletion
    # or revocation. Never remove other paths/repos sharing a content id.
    if is_favorites_id_enabled():
        paths = [normalize_file_path(path), normalize_dir_path(path)]
        relationships = UserStarredFiles.objects.filter(email=email, repo_id=repo_id,
                                                        path__in=paths)
        if org_id != -1:
            relationships = relationships.filter(org_id=org_id)
        relationships.delete()
    else:
        # Preserve the original CE spelling/scope when the extension is off.
        for relationship in UserStarredFiles.objects.filter(email=email, repo_id=repo_id, path=path):
            relationship.delete()


def is_file_starred(email, repo_id, path, org_id=-1):
    if is_favorites_id_enabled():
        # Checking the relation needs no resource RPC and remains correct after
        # file edits or directory-content changes alter the stored content id.
        return UserStarredFiles.objects.filter(
            email=email, org_id=org_id, repo_id=repo_id,
            path__in=[normalize_file_path(path), normalize_dir_path(path)]).exists()

    # Native fallback (also covers a path that no longer resolves).
    path_list = [normalize_file_path(path), normalize_dir_path(path)]
    result = UserStarredFiles.objects.filter(email=email,
            repo_id=repo_id).filter(Q(path__in=path_list))

    n = len(result)
    if n == 0:
        return False
    else:
        # Fix the bug caused by no unique constraint in the table
        if n > 1:
            for r in result[1:]:
                r.delete()
        return True


def get_dir_starred_files(email, repo_id, parent_dir, org_id=-1):
    '''Get starred files under parent_dir.

    '''
    starred_files = UserStarredFiles.objects.filter(email=email,
                                         repo_id=repo_id,
                                         path__startswith=parent_dir,
                                         org_id=org_id)
    return [ normalize_file_path(f.path) for f in starred_files ]


def get_dir_starred_obj_ids(email, repo_id, org_id=-1):
    '''Get the object ids the user has starred, optionally for one repo.

    These ids are diagnostic hints only, never directory-entry star flags:
    multiple resources can share content, and edits change the content id.
    '''
    starred_items = UserStarredFiles.objects.filter(
        email=email, org_id=org_id, obj_id__isnull=False)
    if repo_id is not None:
        starred_items = starred_items.filter(repo_id=repo_id)
    return set(starred_items.values_list('obj_id', flat=True))
