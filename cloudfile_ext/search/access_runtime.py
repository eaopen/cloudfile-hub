"""Fresh bounded legacy-policy reads, deliberately bypassing TTL grant caches."""
import re

from django.db import connection
from seaserv import ccnet_api, seafile_api
from seahub.utils.db_api import SeafileDB
from cloudfile_ext.acl.models import DirACL
from cloudfile_ext.acl.resolver import subject_set
from cloudfile_ext.features import is_enabled


def read_snapshot(username, repo_id):
    account = ccnet_api.get_emailuser(username)
    if account is None or account.is_active not in (True, 1):
        raise ValueError('native account unavailable')
    permission = seafile_api.check_permission(repo_id, username)
    status = seafile_api.get_repo_status(repo_id)
    if permission not in ('r', 'rw') or status not in (0, 1):
        raise ValueError('native library qualification unavailable')
    groups = ccnet_api.get_groups(username)
    if groups is None or len(groups) > 4096:
        raise ValueError('native membership unavailable')
    group_ids, dept_ids, membership, parents = [], [], [], {}
    native_ids = set()
    for group in groups:
        if (type(group.id) is not int or group.id <= 0 or group.id in native_ids or
                type(group.parent_group_id) is not int or group.parent_group_id < -1):
            raise ValueError('invalid membership')
        native_ids.add(group.id)
        membership.append((group.id, group.parent_group_id))
        if group.parent_group_id == 0:
            group_ids.append(group.id)
            continue
        dept_ids.append(group.id)
        parent_id, seen = group.parent_group_id, {group.id}
        while parent_id > 0:
            if parent_id in seen or len(parents) >= 4096:
                raise ValueError('department ancestry unavailable')
            seen.add(parent_id)
            if parent_id not in parents:
                parent = ccnet_api.get_group(parent_id)
                if parent is None:
                    raise ValueError('department ancestry unavailable')
                parents[parent_id] = parent.parent_group_id
                if type(parents[parent_id]) is not int or parents[parent_id] < -1:
                    raise ValueError('department ancestry unavailable')
            dept_ids.append(parent_id)
            parent_id = parents[parent_id]
    enabled = is_enabled('CF_ENABLE_DIR_ACL')
    rules = list(DirACL.objects.filter(repo_id=repo_id).values(
        'path', 'subject_type', 'subject', 'permission', 'inherit')[:4097]) if enabled else []
    if len(rules) > 4096:
        raise ValueError('policy budget exceeded')
    native_ids.update(dept_ids)
    if len(native_ids) > 4095:
        raise ValueError('native membership budget exceeded')
    # Read the target library only. Native folder permissions are inputs to a
    # fresh path-aware narrowing decision, not a global invisible-prefix blacklist.
    database = SeafileDB().db_name
    if not isinstance(database, str) or not re.fullmatch(r'[A-Za-z0-9_]+', database):
        raise ValueError('invalid trusted database')
    with connection.cursor() as sql:
        sql.execute('SELECT path,permission FROM `' + database + '`.FolderUserPerm '
            'WHERE repo_id=%s AND user=%s ORDER BY path,permission LIMIT 4097', (repo_id, username))
        user_rules = list(sql.fetchall())
        group_rules = []
        if native_ids:
            ids = sorted(native_ids)
            sql.execute('SELECT path,permission,group_id FROM `' + database + '`.FolderGroupPerm '
                'WHERE repo_id=%s AND group_id IN (' + ','.join(['%s'] * len(ids)) +
                ') ORDER BY path,permission,group_id LIMIT 4097', (repo_id, *ids))
            group_rules = list(sql.fetchall())
    if len(user_rules) + len(group_rules) > 4096:
        raise ValueError('native folder policy budget exceeded')
    native_rules = [dict(path=row[0], permission=row[1], subject_type='user', subject=username,
        inherit=True) for row in user_rules]
    native_rules.extend(dict(path=row[0], permission=row[1], subject_type='group', subject=str(row[2]),
        inherit=True) for row in group_rules)
    return dict(rules=rules, subjects=sorted(subject_set(username, group_ids, dept_ids)),
        native_rules=native_rules,
        native_subjects=[('user', username)] + [('group', str(gid)) for gid in sorted(native_ids)],
        native_paths=[row[0] for row in user_rules + group_rules],
        state=dict(account_active=True, permission=permission, status=status, acl_enabled=enabled,
            membership=sorted(membership), parents=sorted(parents.items()),
            user_rules=user_rules, group_rules=group_rules))
