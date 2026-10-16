"""Current CE identity and path authority for the existing derived index.

V2 has not yet installed a directory-policy evaluator. Subtrees with cf_dir_acl
rules fail closed here instead of treating a CE library grant as a directory grant.
"""
import hashlib
import json
import posixpath
import stat

from django.db import connection
from django.db.models import Q
from seaserv import ccnet_api, seafile_api
from seahub.file_tags.models import FileTags
from seahub.tags.models import FileTag, FileUUIDMap
from seahub.utils.db_api import SeafileDB
from seahub.utils.ccnet_db import get_ccnet_db_name

from .client import SearchUnavailable, normalize_path


class AccessDenied(Exception):
    pass


def native_tags(repo_id, references):
    """Read only the requested native Tag mappings; never create UUIDs on search."""
    result = {r['path']: [] for r in references}
    if not references:
        return result
    selector = Q(pk__in=[])
    for ref in references:
        parent, name = posixpath.split(ref['path'])
        selector |= Q(repo_id_parent_path_md5=FileUUIDMap.md5_repo_id_parent_path(repo_id, parent),
                      filename=name, is_dir=ref['kind'] == 'dir')
    maps = list(FileUUIDMap.objects.filter(selector, repo_id=repo_id))
    paths = {m.uuid: posixpath.join(m.parent_path, m.filename) for m in maps}
    for uuid, label in FileTags.objects.filter(file_uuid_id__in=paths, repo_tag__repo_id=repo_id).values_list('file_uuid_id', 'repo_tag__name'):
        result[paths[uuid]].append(label)
    for uuid, label in FileTag.objects.filter(uuid_id__in=paths).values_list('uuid_id', 'tag__name'):
        result[paths[uuid]].append(label)
    return {path: sorted(set(labels)) for path, labels in result.items()}


class NativeAuthority:
    def __init__(self, username, repo_id, root):
        self.username, self.repo_id, self.root = username, repo_id, root
        self.snapshot = self.read_snapshot()
        self.version = hashlib.sha256(json.dumps(self.snapshot, sort_keys=True).encode()).hexdigest()

    def read_snapshot(self):
        account = ccnet_api.get_emailuser(self.username)
        if account is None or not account.is_active:
            raise AccessDenied()
        repo = seafile_api.get_repo(self.repo_id)
        permission = seafile_api.check_permission_by_path(self.repo_id, self.root, self.username)
        if repo is None or permission not in ('r', 'rw'):
            raise AccessDenied()
        # Virtual and encrypted repositories need explicit index/path mapping.
        if repo.is_virtual or repo.encrypted:
            raise SearchUnavailable('repository search mapping unavailable')
        schema = connection.ops.quote_name(SeafileDB().db_name)
        accounts = connection.ops.quote_name(get_ccnet_db_name())
        with connection.cursor() as cursor:
            # Only native membership facts bind the cursor; native path RPC
            # remains the authority. Avoid expanding the whole Group hierarchy.
            cursor.execute('SELECT gu.group_id,g.parent_group_id,r.permission FROM ' + accounts + '.GroupUser gu '
                           'JOIN ' + accounts + '.`Group` g ON g.group_id=gu.group_id '
                           'JOIN ' + schema + '.RepoGroup r ON r.group_id=gu.group_id '
                           'WHERE gu.user_name=%s AND r.repo_id=%s ORDER BY gu.group_id,r.permission LIMIT 4097',
                           (self.username, self.repo_id))
            groups = cursor.fetchall()
            if len(groups) > 4096:
                raise SearchUnavailable('native membership budget exceeded')
            cursor.execute('SELECT path,revision FROM ' + schema + '.cf_dir_acl WHERE repo_id=%s ORDER BY path,revision LIMIT 4097', (self.repo_id,))
            acl_rules = cursor.fetchall()
            if len(acl_rules) > 4096:
                raise SearchUnavailable('directory policy budget exceeded')
            for path, revision in acl_rules:
                normalize_path(path)
                if self.root == path or path == '/' or self.root.startswith(path + '/'):
                    raise SearchUnavailable('directory policy evaluator unavailable')
            cursor.execute('SELECT path,permission,user FROM ' + schema + '.FolderUserPerm WHERE repo_id=%s ORDER BY path,user,permission LIMIT 4097', (self.repo_id,))
            user_rules = cursor.fetchall()
            cursor.execute('SELECT path,permission,group_id FROM ' + schema + '.FolderGroupPerm WHERE repo_id=%s ORDER BY path,group_id,permission LIMIT 4097', (self.repo_id,))
            group_rules = cursor.fetchall()
        if len(user_rules) + len(group_rules) > 4096:
            raise SearchUnavailable('native policy budget exceeded')
        return dict(head=repo.head_cmmt_id, permission=permission,
                    status=seafile_api.get_repo_status(self.repo_id),
                    groups=groups,
                    user_rules=user_rules, group_rules=group_rules, acl_rules=acl_rules)

    def resolve(self, references):
        tags = native_tags(self.repo_id, references)
        result = []
        for ref in references:
            path, kind = ref['path'], ref['kind']
            if any(root == '/' or path == root or path.startswith(root + '/')
                   for root, revision in self.snapshot['acl_rules']):
                result.append(None)
                continue
            permission = seafile_api.check_permission_by_path(self.repo_id, path, self.username)
            if permission not in ('r', 'rw'):
                result.append(None)
                continue
            entry = seafile_api.get_dirent_by_path(self.repo_id, path)
            if entry is None or (stat.S_ISDIR(entry.mode) if kind == 'dir' else stat.S_ISREG(entry.mode)) is False:
                result.append(None)
                continue
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
        if self.read_snapshot() != self.snapshot:
            raise SearchUnavailable('library or authorization changed')
        current = self.resolve(references)
        if current != references:
            raise SearchUnavailable('object authorization or metadata changed')
