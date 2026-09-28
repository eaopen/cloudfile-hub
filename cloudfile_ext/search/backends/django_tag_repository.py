# -*- coding: utf-8 -*-
"""Django-backed data access for the built-in tag search backend.

Split out from ``dbtags`` so the query logic stays importable (and testable)
without Django: ``DbTagsProvider`` imports this module lazily, tests inject a
fake repository.

Both tag stores are read, because the deployment has both:

* v2 (``repo_tags_repotags`` / ``file_tags_filetags``) -- system tags and v2 user
  tags; files only;
* legacy (``tags_tags`` / ``tags_filetag``) -- the free-text user tags the portal
  still writes, which also cover folders.

``tags_fileuuidmap`` is the shared object identity in both stores, so a tag name
resolves to a path by joining through it.
"""

import logging
import posixpath

logger = logging.getLogger(__name__)

#: Guard against a pathological size/time-filtered query resolving a dirent per
#: candidate. Beyond this the caller gets an explicit refusal instead of a slow
#: request or a silently truncated answer.
MAX_DIRENT_LOOKUPS = 500


class DjangoTagRepository(object):

    def find_rows(self, repo_ids, tag_names, with_dirents=False):
        """Rows for every object in ``repo_ids`` carrying one of ``tag_names``.

        Each row is ``{repo_id, path, name, is_dir, tags, size, mtime}`` where
        ``tags`` is the object's *complete* tag set across both stores (so the
        hit can report every tag, not just the matched one). ``size``/``mtime``
        stay ``None`` unless ``with_dirents`` was requested -- they cost one
        dirent lookup per row.
        """
        repo_ids = [r for r in (repo_ids or []) if r]
        if not repo_ids or not tag_names:
            return []

        uuid_maps = self._uuid_maps_for_tags(repo_ids, tag_names)
        if not uuid_maps:
            return []

        tags_by_uuid = self._tags_by_uuid(list(uuid_maps.keys()))
        rows = []
        dirent_lookups = 0
        for uuid, uuid_map in uuid_maps.items():
            path = self._path_of(uuid_map)
            row = {
                'repo_id': uuid_map.repo_id,
                'path': path,
                'name': uuid_map.filename,
                'is_dir': bool(uuid_map.is_dir),
                'tags': tags_by_uuid.get(uuid, []),
                'size': None,
                'mtime': None,
            }
            if with_dirents:
                dirent_lookups += 1
                if dirent_lookups > MAX_DIRENT_LOOKUPS:
                    raise RuntimeError(
                        'too many candidates (%d) to resolve dirents for a '
                        'size/time filter; narrow the tag filter or select an '
                        'index provider' % dirent_lookups)
                self._fill_dirent(row, uuid_map)
            rows.append(row)
        return rows

    # -- internals ---------------------------------------------------------

    def _uuid_maps_for_tags(self, repo_ids, tag_names):
        from seahub.file_tags.models import FileTags
        from seahub.tags.models import FileTag

        uuid_maps = {}
        for file_tag in FileTags.objects.filter(
                repo_tag__repo_id__in=repo_ids,
                repo_tag__name__in=tag_names).select_related('file_uuid'):
            uuid_maps[file_tag.file_uuid_id] = file_tag.file_uuid
        for file_tag in FileTag.objects.filter(
                uuid__repo_id__in=repo_ids,
                tag__name__in=tag_names).select_related('uuid'):
            uuid_maps[file_tag.uuid_id] = file_tag.uuid
        return uuid_maps

    def _tags_by_uuid(self, uuids):
        """Complete tag set per object across both stores (order preserved)."""
        from seahub.file_tags.models import FileTags
        from seahub.tags.models import FileTag

        tags = {uuid: [] for uuid in uuids}
        for file_tag in FileTags.objects.filter(
                file_uuid_id__in=uuids).select_related('repo_tag'):
            names = tags.setdefault(file_tag.file_uuid_id, [])
            if file_tag.repo_tag.name not in names:
                names.append(file_tag.repo_tag.name)
        for file_tag in FileTag.objects.filter(
                uuid_id__in=uuids).select_related('tag'):
            names = tags.setdefault(file_tag.uuid_id, [])
            if file_tag.tag.name not in names:
                names.append(file_tag.tag.name)
        return tags

    def _path_of(self, uuid_map):
        parent = uuid_map.parent_path or '/'
        return posixpath.join(parent, uuid_map.filename)

    def _fill_dirent(self, row, uuid_map):
        """Attach size/mtime from the dirent; failures leave them ``None``."""
        from seaserv import seafile_api

        try:
            repo = seafile_api.get_repo(uuid_map.repo_id)
            if not repo:
                return
            dirent = seafile_api.get_dirent_by_path(repo.store_id, row['path'])
            if not dirent:
                return
            row['size'] = None if row['is_dir'] else getattr(dirent, 'size', None)
            row['mtime'] = getattr(dirent, 'mtime', None)
        except Exception:
            logger.warning('dbtags: could not read dirent for %s/%s',
                           uuid_map.repo_id, row['path'], exc_info=True)
