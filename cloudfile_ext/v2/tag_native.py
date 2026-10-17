"""Small CE RepoTags/FileTags permission bridge for V2 native endpoints.

No new models, metadata server, caches or feature toggles. The current user
and target native object are checked before revealing or mutating tag bindings.
"""
import stat

from .acl_policy import canonical_path
from .acl_runtime import Authority
from .acl_http import require_repo_manage


def authorize_tag_target(user, repo_id, path, is_dir=False, write=False):
    if path == '/':
        raise ValueError('root cannot be tagged')
    canonical_path(path)
    kind = 'dir' if is_dir else 'file'
    authority = Authority(user.username)
    decision = authority.effective(repo_id, path, kind)
    if not (decision.can_write if write else decision.can_read):
        raise PermissionError('no current native and directory ACL grant')
    entry = authority.api.get_dirent_by_path(repo_id, path)
    if entry is None or not hasattr(entry, 'mode'):
        raise FileNotFoundError('tag target does not exist')
    if not (stat.S_ISDIR(entry.mode) if is_dir else stat.S_ISREG(entry.mode)):
        raise FileNotFoundError('tag target kind mismatch')
    return path


def authorize_tag_label(user, repo_id, name):
    """SYS_ is a reserved EAP namespace, never an ordinary user binding."""
    if not isinstance(name, str) or not name:
        raise ValueError('invalid tag name')
    if name.upper().startswith('SYS_'):
        require_repo_manage(user, repo_id)


def require_repo_tag(repo_id, repo_tag):
    if repo_tag is None or repo_tag.repo_id != repo_id:
        raise FileNotFoundError('tag definition outside requested repository')
    return repo_tag


def user_tag_names(names):
    """Keep the existing comma-separated user-label contract, never SYS_."""
    import re
    if not isinstance(names, str):
        raise ValueError('invalid user tag names')
    values = [part.strip() for part in names.split(',')] if names.strip() else []
    if len(values) > 128 or any(
            not value or len(value) > 255 or not re.fullmatch(r'[.\w-]+', value, re.U)
            for value in values):
        raise ValueError('invalid native user tag names')
    for value in values:
        if value.upper().startswith('SYS_'):
            raise PermissionError('reserved system label')
    return list(dict.fromkeys(values))


def read_resource_tags(repo_id, path, is_dir):
    """Both native CE sources remain visible; legacy bindings are read-only."""
    from .tag_reads import read
    reference = (path, 'dir' if is_dir else 'file')
    rows = read(repo_id, [reference])[reference]
    return [dict(id=row.get('repo_tag_id', row.get('legacy_tag_id')),
                 name=row['tag_name'], source=row['source'],
                 read_only=row['source'] == 'legacy') for row in rows]


def _definition(repo_id, name):
    from seahub.repo_tags.models import RepoTags
    tag = RepoTags.objects.get_repo_tag_by_name(repo_id, name)
    return tag if tag is not None else RepoTags.objects.create_repo_tag(repo_id, name, '#6B7280')
