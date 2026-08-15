# Copyright (c) 2012-2016 Seafile Ltd.
# -*- coding: utf-8 -*-
import logging

from django.db import IntegrityError
from django.db.models import Q

from seaserv import seafile_api

from seahub.base.models import UserStarredFiles
from seahub.utils import normalize_file_path, normalize_dir_path
from cloudfile_ext.favorites.identity import pick_obj_id, should_backfill

logger = logging.getLogger(__name__)


def is_favorites_id_enabled():
    """Whether favorites are keyed by object id rather than repo_id + path.

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
    """Fill a row's obj_id from its stored repo_id + path, if missing.

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

    if obj_id:
        # Key by object identity. Starring the same object again re-homes the
        # existing row (e.g. after a move/rename) instead of creating a
        # duplicate, so a favorite follows its object rather than its path.
        existing = UserStarredFiles.objects.filter(
            email=email, org_id=org_id, obj_id=obj_id).first()
        if existing is not None:
            if (existing.repo_id != repo_id or existing.path != path or
                    existing.is_dir != is_dir):
                existing.repo_id = repo_id
                existing.path = path
                existing.is_dir = is_dir
                existing.save()
            return

        try:
            UserStarredFiles.objects.create(email=email,
                                            org_id=org_id,
                                            repo_id=repo_id,
                                            path=path,
                                            is_dir=is_dir,
                                            obj_id=obj_id)
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
    obj_id = None
    if is_favorites_id_enabled():
        obj_id = resolve_obj_id(repo_id, path)

    if obj_id:
        # Match the object id only: the legacy /api2/starredfiles/ endpoint
        # hardcodes org_id=-1, so filtering on org_id here would silently fail
        # to unstar for org users.
        UserStarredFiles.objects.filter(email=email, obj_id=obj_id).delete()
        return

    # Native fallback: the path may not resolve (deleted/moved), so unstar by
    # whatever the row stores.
    result = UserStarredFiles.objects.filter(email=email,
                                             repo_id=repo_id,
                                             path=path)
    for r in result:
        r.delete()


def is_file_starred(email, repo_id, path, org_id=-1):
    if is_favorites_id_enabled():
        obj_id = resolve_obj_id(repo_id, path)
        if obj_id:
            return UserStarredFiles.objects.filter(
                email=email, org_id=org_id, obj_id=obj_id).exists()

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

    Used to mark directory-listing entries by object id rather than path, so a
    renamed/moved item keeps its star even when the path-keyed rows have not
    been re-homed yet. Only rows that already carry an obj_id participate.
    '''
    starred_items = UserStarredFiles.objects.filter(
        email=email, org_id=org_id, obj_id__isnull=False)
    if repo_id is not None:
        starred_items = starred_items.filter(repo_id=repo_id)
    return set(starred_items.values_list('obj_id', flat=True))
