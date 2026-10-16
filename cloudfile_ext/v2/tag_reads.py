"""Batch reads of native CE tags for known file/directory references.

Shared by directory pages and search results: two indexed queries per batch
(library tags, then legacy free tags), grouped by parent directory. Reads only
existing FileUUIDMap rows and never creates UUIDs. Tags never authorize
anything; callers pass references that are already visible to the user.
"""
import posixpath

from django.db.models import Q

MAX_REFERENCES = 1000
MAX_ROWS = 10000


def _selector(repo_id, references, relation):
    from seahub.tags.models import FileUUIDMap
    names = {}
    for path, _ in references:
        parent, name = posixpath.split(path)
        names.setdefault(parent, set()).add(name)
    selector = Q(pk__in=[])
    for parent, children in names.items():
        selector |= Q(**{relation + '__repo_id_parent_path_md5': FileUUIDMap.md5_repo_id_parent_path(repo_id, parent),
                         relation + '__filename__in': sorted(children)})
    return selector & Q(**{relation + '__repo_id': repo_id})


def _bounded(queryset, fields):
    rows = list(queryset.values_list(*fields).order_by('pk')[:MAX_ROWS + 1])
    if len(rows) > MAX_ROWS:
        raise ValueError('tag read budget exceeded')
    return rows


def read(repo_id, references):
    """references: [(path, 'file'|'dir')]; returns {(path, kind): [tag, ...]}.

    Library tags carry ids and color; legacy free tags are read-only display.
    """
    result = {(path, kind): [] for path, kind in references}
    if not result:
        return result
    if len(result) > MAX_REFERENCES:
        raise ValueError('tag reference budget exceeded')
    from seahub.file_tags.models import FileTags
    from seahub.tags.models import FileTag

    def target(parent, filename, is_dir):
        key = (posixpath.join(parent, filename), 'dir' if is_dir else 'file')
        return result.get(key)

    rows = _bounded(FileTags.objects.filter(_selector(repo_id, result, 'file_uuid'), repo_tag__repo_id=repo_id),
                    ('pk', 'repo_tag_id', 'repo_tag__name', 'repo_tag__color',
                     'file_uuid__parent_path', 'file_uuid__filename', 'file_uuid__is_dir'))
    for pk, tag_id, name, color, parent, filename, is_dir in rows:
        items = target(parent, filename, is_dir)
        if items is not None:
            items.append(dict(source='repo', file_tag_id=pk, repo_tag_id=tag_id, tag_name=name, tag_color=color))
    rows = _bounded(FileTag.objects.filter(_selector(repo_id, result, 'uuid')),
                    ('pk', 'tag__name', 'uuid__parent_path', 'uuid__filename', 'uuid__is_dir'))
    for pk, name, parent, filename, is_dir in rows:
        items = target(parent, filename, is_dir)
        if items is not None:
            items.append(dict(source='legacy', legacy_tag_id=pk, tag_name=name, read_only=True))
    return result
