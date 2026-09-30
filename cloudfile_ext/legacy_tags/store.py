"""Legacy UUID/FileTag/Tags collection reads, never RepoTags or cf_tag."""
import posixpath

from django.db import router, transaction
from django.db.models import Q
from seahub.tags.models import FileTag, FileUUIDMap

from .contract import MAX_ITEMS

MAX_BINDINGS = 2000


def tags_many(repo_id, repo, items):
    if not items:
        return {}
    if len(items) > MAX_ITEMS:
        raise ValueError('Too many legacy tag references')
    # Reuse the already loaded repo's virtual-origin mapping, rather than the
    # scalar UUID manager's repeated get_repo RPC. Root uses the legacy empty
    # parent/name pair; changing it to '/' would change its stored UUID key.
    groups, keys = {}, {}
    origin = repo.origin_repo_id if repo.is_virtual else repo_id
    for path, is_dir in items:
        parent, name = posixpath.split(path.rstrip('/'))
        if repo.is_virtual:
            parent = posixpath.join(repo.origin_path, parent.strip('/'))
        parent = FileUUIDMap.normalize_path(parent)
        digest = FileUUIDMap.md5_repo_id_parent_path(origin, parent)
        groups.setdefault((digest, is_dir), set()).add(name)
        keys[(digest, name, is_dir)] = (path, is_dir, parent)
    condition = Q()
    for (digest, is_dir), names in groups.items():
        condition |= Q(repo_id_parent_path_md5=digest, filename__in=sorted(names), is_dir=is_dir)
    result = {item: [] for item in items}
    alias = router.db_for_read(FileTag)
    with transaction.atomic(using=alias):
        # Indexed hash/name/type predicates bound the collection even across
        # many parents. Sparse reads never allocate a UUID or touch a tag.
        rows = list(FileUUIDMap.objects.using(alias).filter(condition).order_by('uuid')[:MAX_ITEMS + 1])
        if len(rows) > len(items):
            raise ValueError('Ambiguous legacy UUID mapping')
        by_uuid, seen = {}, set()
        for row in rows:
            key = (row.repo_id_parent_path_md5, row.filename, row.is_dir)
            if key not in keys or key in seen:
                raise ValueError('Unexpected legacy UUID mapping')
            path, is_dir, parent = keys[key]
            # Do not allow a collation/hash mismatch to alias another identity.
            if row.repo_id != origin or row.parent_path != parent:
                raise ValueError('Legacy UUID identity mismatch')
            seen.add(key)
            by_uuid[row.pk] = (path, is_dir)
        if by_uuid:
            # One bounded join supplies bindings AND definitions, preserving
            # binding/insertion order rather than sorting by label or tag ID.
            bindings = list(FileTag.objects.using(alias).filter(uuid_id__in=by_uuid)
                            .select_related('tag').order_by('pk')[:MAX_BINDINGS + 1])
            if len(bindings) > MAX_BINDINGS:
                raise ValueError('Legacy tag response budget exceeded')
            for binding in bindings:
                result[by_uuid[binding.uuid_id]].append(binding.to_dict())
    return result
