"""Sparse library display cache; authorization is always outside this cache."""
import posixpath
import time

from django.conf import settings
from django.core.cache import cache
from seahub.tags.models import FileTag


def tags_for_page(repo_id, repo, items):
    origin = repo.origin_repo_id if repo.is_virtual else repo_id
    key = 'cf_display_tags_v1_' + origin
    tags = cache.get(key)
    if tags is None:
        started = time.monotonic()
        tags = {}
        # Start at bindings, not UUIDs: libraries with no tags cache just {}.
        # Join definitions once; failed reads must never cache an empty result.
        bindings = FileTag.objects.filter(uuid__repo_id=origin).select_related('uuid', 'tag').order_by('pk')
        for binding in bindings.iterator(chunk_size=1000):
            row = binding.uuid
            path = posixpath.join(row.parent_path, row.filename).rstrip('/') or '/'
            tags.setdefault((path, row.is_dir), []).append(binding.to_dict())
        # Start expiry at the SQL read, so a slow refill cannot outlive the
        # editor's three-minute confirmation window after a concurrent write.
        remaining = int(getattr(settings, 'CF_DISPLAY_TAG_CACHE_TTL', 180) - (time.monotonic() - started))
        if remaining > 0:
            cache.set(key, tags, remaining)
    result = {}
    for path, is_dir in items:
        original = posixpath.join(repo.origin_path, path.lstrip('/')) if repo.is_virtual else path
        result[(path, is_dir)] = tags.get((original.rstrip('/') or '/', is_dir), [])
    return result
