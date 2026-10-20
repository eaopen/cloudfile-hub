"""Full Etech org/role and GroupUser reconciliation using the existing V2 UID map.

The trusted EAP snapshot and entity catalog must agree before any native writes.
Native Group/GroupStructure, group members and library shares remain in their
original CE tables. No legacy worker, second mapping table, or user-name merge.
"""
from collections import defaultdict
from datetime import datetime, timezone

from .errors import IdentityUnavailable
from .identity import text
from .schema import database_lock, identifier
from .memberships import readiness_key


MAX_MEMBERSHIPS = 500000
MAX_REMOVE_RATIO = 0.5


def snapshot_members(snapshot, entities):
    """Verify the full EAP snapshot against the signed catalog and expand org parents.

    EAP snapshot uses dept/group with 'role:<id>'; current V2 identity uses
    org/role with explicit namespace. The name/parent must be identical.
    Unknown groups, duplicate member UIDs and mismatched parents refuse writes.
    """
    try:
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get('groups'), list):
            raise ValueError()
        rows = snapshot['groups']
        if not rows or len(rows) != len(entities):
            raise ValueError()
        result = {}
        total = 0
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError()
            kind = row['subject_type']
            source = text(row['external_id'])
            key = ('role', 'role', source[5:]) if kind == 'group' and source.startswith('role:') \
                else ('org', 'directory', source) if kind == 'dept' else None
            if key is None or key not in entities or key in result:
                raise ValueError()
            parent = row.get('parent_external_id')
            parent_key = None if parent is None else ('org', 'directory', text(parent))
            if parent_key != entities[key]['parent'] or row.get('name') != entities[key]['name']:
                raise ValueError()
            uids = row.get('member_user_ids')
            if not isinstance(uids, list):
                raise ValueError()
            members = {text(uid) for uid in uids}
            if len(members) != len(uids):
                raise ValueError()
            total += len(members)
            if total > MAX_MEMBERSHIPS:
                raise ValueError()
            result[key] = members
        if set(result) != set(entities):
            raise ValueError()
        # Native CE hierarchy and current-user TTL projection must agree:
        # a child's effective members belong to every trusted parent, too.
        for key in reversed(list(entities)):
            parent = entities[key]['parent']
            if parent is not None:
                result[parent].update(result[key])
        return result
    except (KeyError, TypeError, ValueError, IndexError):
        raise IdentityUnavailable('incomplete or inconsistent full Etech directory snapshot') from None


def native_users(connection, schema, uids):
    """Resolve only exact existing UID/Profile and active CE accounts; no JIT.

    Unknown/ambiguous UIDs quarantine removals for their groups. This prevents
    full sync from fabricating a new account, discarding an authorized member,
    or transferring a shared library via a reused employee number.
    """
    bound, ambiguous = {}, set()
    profile = identifier(schema) + '.profile_profile'
    from seahub.utils.ccnet_db import get_ccnet_db_name
    accounts = identifier(get_ccnet_db_name()) + '.EmailUser'
    requested = set(uids)
    for start in range(0, len(uids), 400):
        batch = uids[start:start + 400]
        if not batch:
            continue
        with connection.cursor() as cursor:
            cursor.execute('SELECT p.user,p.login_id,e.email,e.is_active FROM ' + profile +
                           ' p JOIN ' + accounts + ' e ON e.email=p.user WHERE p.login_id IN (' +
                           ','.join(['%s'] * len(batch)) + ')', tuple(batch))
            for username, uid, native, active in cursor.fetchall():
                if (uid not in requested or not isinstance(username, str)
                        or username != native or type(active) not in (int, bool)
                        or active != 1 or uid in bound):
                    ambiguous.add(uid)
                else:
                    bound[uid] = username
    native_owners = defaultdict(set)
    for uid, username in bound.items():
        native_owners[username.lower()].add(uid)
    for owners in native_owners.values():
        if len(owners) != 1:
            ambiguous.update(owners)
    for uid in ambiguous:
        bound.pop(uid, None)
    return bound


def _read_native(cursor, table, ids):
    cursor.execute('SELECT group_id,parent_group_id FROM ' + table +
                   ' WHERE group_id IN (' + ','.join(['%s'] * len(ids)) + ') FOR UPDATE', tuple(ids))
    rows = cursor.fetchall()
    if len(rows) != len(ids) or len({group for group, _ in rows}) != len(ids):
        raise IdentityUnavailable('mapped native Group is missing')
    return dict(rows)


def apply_snapshot(connection, catalog, entities, ids, members, *, native_users_by_uid, cache, database):
    """One locked transaction for hierarchy + membership changes.

    Never change a non-mapped group. A native child not owned by the current
    map makes reparenting unsafe and refuses the entire publication.
    """
    from .schema import identifier
    group_table = catalog.groups
    schema = group_table.split('.')[0]
    structure = schema + '.GroupStructure'
    group_user = schema + '.GroupUser'
    all_ids = sorted(ids.values())
    if not all_ids or len(set(all_ids)) != len(all_ids):
        raise IdentityUnavailable('native group mapping conflict')
    changes, renamed, changed_users = 0, 0, set()
    unresolved = set()
    wanted = {}
    for key in entities:
        raw = members[key]
        missing = raw - native_users_by_uid.keys()
        unresolved.update(missing)
        wanted[key] = {native_users_by_uid[uid] for uid in raw if uid in native_users_by_uid}
    # A missing identity means the existing group cannot safely lose anyone.
    quarantined = {key for key in entities if members[key] - native_users_by_uid.keys()}

    with database_lock(connection, 'groups:' + catalog.provider):
        connection.begin()
        try:
            with connection.cursor() as cursor:
                # Group, GroupStructure, GroupUser and ownership mapping must
                # participate in the same transaction before any hierarchy or
                # membership changes. No implicit nontransactional fallback.
                cursor.execute('SELECT DATABASE()')
                cloud_schema = cursor.fetchone()[0]
                for table_schema, table_name in (
                        (schema.strip('`'), 'Group'),
                        (schema.strip('`'), 'GroupStructure'),
                        (schema.strip('`'), 'GroupUser'),
                        (cloud_schema, 'cf_sso_group_map')):
                    cursor.execute('SELECT ENGINE FROM information_schema.tables '
                                   'WHERE table_schema=%s AND table_name=%s',
                                   (table_schema, table_name))
                    if cursor.fetchall() != (('InnoDB',),):
                        raise IdentityUnavailable('native directory storage is not transactional')
                actual = _read_native(cursor, group_table, all_ids)
                cursor.execute('SELECT group_id,parent_group_id FROM ' + group_table +
                               ' WHERE parent_group_id IN (' + ','.join(['%s'] * len(all_ids)) + ')',
                               tuple(all_ids))
                if any(child not in all_ids for child, parent in cursor.fetchall()):
                    raise IdentityUnavailable('unmanaged native child prevents parent reconciliation')
                expected = {}
                for key in entities:  # Directory.entities is parent-first.
                    gid = ids[key]
                    parent = entities[key]['parent']
                    if key[0] == 'role':
                        expected[gid] = (0, None)
                        if actual[gid] != 0:
                            raise IdentityUnavailable('role group cannot be a department')
                    else:
                        if parent is None:
                            expected[gid] = (-1, str(gid))
                        else:
                            if parent not in ids:
                                raise IdentityUnavailable('directory parent missing')
                            parent_id = ids[parent]
                            expected[gid] = (parent_id, expected[parent_id][1] + ', ' + str(gid))
                        if actual[gid] < -1:
                            raise IdentityUnavailable('invalid existing native department')
                cursor.execute('SELECT group_id,path FROM ' + structure +
                               ' WHERE group_id IN (' + ','.join(['%s'] * len(all_ids)) + ') FOR UPDATE',
                               tuple(all_ids))
                paths = dict(cursor.fetchall())
                for gid, (parent, path) in expected.items():
                    if parent == 0:
                        if gid in paths:
                            raise IdentityUnavailable('flat role unexpectedly has department structure')
                        continue
                    if actual[gid] != parent:
                        cursor.execute('UPDATE ' + group_table +
                                       ' SET parent_group_id=%s WHERE group_id=%s AND parent_group_id=%s',
                                       (parent, gid, actual[gid]))
                        if cursor.rowcount != 1:
                            raise IdentityUnavailable('native group parent changed concurrently')
                        changes += 1
                    if paths.get(gid) != path:
                        if gid in paths:
                            cursor.execute('UPDATE ' + structure + ' SET path=%s WHERE group_id=%s',
                                           (path, gid))
                        else:
                            cursor.execute('INSERT INTO ' + structure + '(group_id,path) VALUES(%s,%s)',
                                           (gid, path))
                        if cursor.rowcount != 1:
                            raise IdentityUnavailable('native group path publication failed')
                        changes += 1
                # Check every managed group (and its non-staff members), without
                # scanning unrelated manual groups or any RepoGroup share.
                existing = defaultdict(set)
                protected = defaultdict(set)
                for start in range(0, len(all_ids), 100):
                    part = all_ids[start:start + 100]
                    cursor.execute('SELECT group_id,user_name,is_staff FROM ' + group_user +
                                   ' WHERE group_id IN (' + ','.join(['%s'] * len(part)) +
                                   ') FOR UPDATE', tuple(part))
                    for gid, user, staff in cursor.fetchall():
                        if staff == 0:
                            existing[gid].add(user)
                        elif staff == 1:
                            protected[gid].add(user)
                        else:
                            raise IdentityUnavailable('invalid native group staff marker')
                adds, removes = [], []
                for key, gid in ids.items():
                    desired = wanted[key] - protected[gid]
                    adds.extend((gid, user) for user in sorted(desired - existing[gid]))
                    if key not in quarantined:
                        removes.extend((gid, user) for user in sorted(existing[gid] - desired))
                count_existing = sum(len(value) for value in existing.values())
                if count_existing and len(removes) > count_existing * MAX_REMOVE_RATIO:
                    raise IdentityUnavailable('unexpected mass group removal refused')
                # Invalid identity never silently empties a group; remove only
                # fully trusted source groups. Admin/creator rows are untouched.
                for gid, user in removes:
                    cursor.execute('DELETE FROM ' + group_user +
                                   ' WHERE group_id=%s AND user_name=%s AND is_staff=0', (gid, user))
                    if cursor.rowcount != 1:
                        raise IdentityUnavailable('native membership changed concurrently')
                    changed_users.add(user)
                for gid, user in adds:
                    cursor.execute('INSERT INTO ' + group_user +
                                   '(group_id,user_name,is_staff) VALUES(%s,%s,0)', (gid, user))
                    if cursor.rowcount != 1:
                        raise IdentityUnavailable('native membership write failed')
                    changed_users.add(user)
                changes_members = len(adds) + len(removes)
            connection.commit()
        finally:
            connection.rollback()
    # The full sync and on-login per-UID projector share GroupUser. Expire its
    # readiness for touched identities; a subsequent request rechecks Directory.
    for username in changed_users:
        for uid, owner in native_users_by_uid.items():
            if owner == username:
                cache.delete(readiness_key(database, catalog.provider, uid, username))
    return dict(status='PARTIAL' if unresolved else 'OK', members_added=len(adds),
                members_removed=len(removes), membership_writes=changes_members,
                parent_writes=changes, unresolved_count=len(unresolved),
                unresolved_user_ids=sorted(unresolved)[:100], quarantined_groups=len(quarantined))


def synchronize(directory, catalog, cache, database):
    """Full manual/PowerJob synchronization, same old endpoint and existing mapping."""
    from seaserv import ccnet_api
    entities = directory.entities()
    if not entities:
        raise IdentityUnavailable('empty entity catalog cannot be synchronized')
    # Validate all memberships and parent links BEFORE creating native groups.
    members = snapshot_members(directory.snapshot(), entities)
    ids, renamed = {}, 0
    for key, entry in entities.items():
        gid = catalog.ensure(*key, entry['name'])
        ids[key] = gid
        actual = ccnet_api.get_group(gid)
        if actual is None:
            raise IdentityUnavailable('mapped native group missing')
        if actual.group_name != entry['name']:
            ccnet_api.set_group_name(gid, entry['name'])
            if ccnet_api.get_group(gid).group_name != entry['name']:
                raise IdentityUnavailable('native group name update failed')
            renamed += 1
    all_uids = sorted({uid for group in members.values() for uid in group})
    from django.conf import settings
    bound = native_users(catalog.connection, settings.DATABASES['default']['NAME'], all_uids)
    result = apply_snapshot(catalog.connection, catalog, entities, ids, members,
                            native_users_by_uid=bound, cache=cache, database=database)
    return dict(result, entities=len(entities), renamed=renamed)
