"""Display-only CE tags for files and directories on an authorized page.

Facts are native RepoTags + FileTags + FileUUIDMap only; no CloudFile table.
Tags never authorize anything: callers pass entries already filtered by ACL,
so hidden objects and the rest of the library vocabulary are never returned.
"""
import posixpath

from django.db import transaction

from . import library_cache

NAMESPACE = 'cf-tags-v1'
# Bindings per library kept in the shared snapshot. Larger libraries read the
# current page instead; FileUUIDMap is never scanned for untagged objects.
BUDGET = 10000
FIELDS = ('pk', 'repo_tag_id', 'repo_tag__name', 'repo_tag__color', 'file_uuid__repo_id',
          'file_uuid__parent_path', 'file_uuid__filename', 'file_uuid__is_dir')


def cache_ttl():
    return library_cache.ttl('CF_TAG_CACHE_TTL', 180)


def _bounded(queryset):
    rows = [tuple(row) for row in queryset.values_list(*FIELDS).order_by('pk')[:BUDGET + 1]]
    return None if len(rows) > BUDGET else rows


def read_library(repo_id):
    from seahub.file_tags.models import FileTags
    # Start at the library's tag dictionary: untagged libraries cost one probe.
    return _bounded(FileTags.objects.filter(repo_tag__repo_id=repo_id))


def read_page(repo_id, parent, names):
    from seahub.file_tags.models import FileTags
    from seahub.tags.models import FileUUIDMap
    digest = FileUUIDMap.md5_repo_id_parent_path(repo_id, parent)
    rows = _bounded(FileTags.objects.filter(repo_tag__repo_id=repo_id, file_uuid__repo_id_parent_path_md5=digest,
                                            file_uuid__filename__in=names))
    if rows is None:
        raise ValueError('tag page budget exceeded')
    return rows


def _decode(rows):
    result = []
    for row in rows:
        pk, tag_id, name, color, repo_id, parent, filename, is_dir = row
        if (type(pk) is not int or type(tag_id) is not int or type(is_dir) is not bool or
                not all(isinstance(v, str) for v in (name, color, repo_id, parent, filename))):
            raise ValueError('malformed cached tag row')
        result.append(tuple(row))
    return result


def tags_for_entries(repo_id, parent, entries):
    """entries: [(path, kind)] in `parent`; returns {(path, kind): [tag, ...]}."""
    if not entries:
        return {}
    rows = library_cache.snapshot(NAMESPACE, repo_id, cache_ttl(), lambda: read_library(repo_id),
                                  lambda data: [list(row) for row in data], _decode)
    if rows is None:
        rows = read_page(repo_id, parent, sorted({posixpath.basename(path) for path, _ in entries}))
    wanted = {entry: [] for entry in entries}
    for pk, tag_id, name, color, owner, parent_path, filename, is_dir in rows:
        # A binding whose object or tag belongs elsewhere is never displayed.
        key = (posixpath.join(parent_path, filename), 'dir' if is_dir else 'file')
        if owner == repo_id and key in wanted:
            wanted[key].append(dict(file_tag_id=pk, repo_tag_id=tag_id, tag_name=name, tag_color=color))
    return wanted


def invalidate(repo_id):
    transaction.on_commit(lambda: library_cache.invalidate(NAMESPACE, repo_id))


def connect_invalidation():
    """Native tag writes switch the library snapshot after commit.

    Bulk SQL or external processes (e.g. path updates outside Seahub models)
    are bounded by the TTL instead. A receiver failure never breaks a write.
    """
    from django.db.models.signals import post_save, pre_delete
    from seahub.file_tags.models import FileTags
    from seahub.repo_tags.models import RepoTags
    from seahub.tags.models import FileUUIDMap

    def owner(sender, instance):
        if sender is FileTags:
            return RepoTags.objects.filter(pk=instance.repo_tag_id).values_list('repo_id', flat=True).first()
        return instance.repo_id

    def changed(sender, instance, **kwargs):
        try:
            repo_id = owner(sender, instance)
            if repo_id:
                invalidate(repo_id)
        except Exception:
            library_cache.logger.warning('CloudFile tag cache invalidation skipped', exc_info=True)

    for model in (RepoTags, FileTags, FileUUIDMap):
        for name, signal in (('save', post_save), ('delete', pre_delete)):
            signal.connect(changed, sender=model, weak=False,
                           dispatch_uid='cf-tags-%s-%s' % (model.__name__, name))
