"""Reconcile eTech's v0.1 full snapshot with owned native groups.

The stable org_user/org_group/org_role IDs are the only mapping keys. The
v0.1 snapshot validator and reconciler are reused; the adapter below only
translates ``role:<id>`` into the current role namespace and persists the
existing native group ID.
"""
import logging
import time

from django.conf import settings
from seaserv import ccnet_api, seafile_api
from seahub.base.accounts import User

from ..authorization.service_configuration import directory_authorization
from ..common.http import HttpsJsonClient, trusted_https_url
from ..common.validation import identifier
from ..library_shares import _database
from . import reconcile, snapshot
from .project import qualified


logger = logging.getLogger(__name__)


def _mapping(external_id, kind):
    if kind == 'dept':
        identifier(external_id)
        return 'dept', 'directory', external_id
    if kind == 'group' and external_id.startswith('role:'):
        role_id = external_id[5:]
        identifier(role_id)
        return 'group', 'role', role_id
    raise snapshot.SnapshotRejected('only eTech department and role IDs are supported')


def _read_mapped(cursor, provider):
    cursor.execute('SELECT subject_type,namespace,external_id,group_id,name,parent_external_id '
                   'FROM cf_sso_group_map WHERE provider=%s ORDER BY id', (provider,))
    mapped = {}
    for kind, namespace, external_id, group_id, name, parent in cursor.fetchall():
        key = external_id if kind == 'dept' and namespace == 'directory' else 'role:' + external_id if kind == 'group' and namespace == 'role' else None
        if key is None or key in mapped or type(group_id) is not int or group_id <= 0:
            raise ValueError('unsupported existing group mapping')
        mapped[key] = dict(group_id=group_id, name=name, parent_external_id=parent)
    return mapped


def _bound_users(cursor, user_ids, identity_schema):
    profile = qualified(identity_schema, 'profile_profile')
    usernames = {}
    for start in range(0, len(user_ids), 500):
        batch = user_ids[start:start + 500]
        cursor.execute('SELECT user,login_id FROM ' + profile + ' WHERE login_id IN (' + ','.join(['%s'] * len(batch)) + ')', tuple(batch))
        for username, user_id in cursor.fetchall():
            identifier(username)
            if user_id in usernames and usernames[user_id] != username:
                raise ValueError('ambiguous business identity binding')
            usernames[user_id] = username
    if len(set(usernames.values())) != len(usernames):
        raise ValueError('multiple business users share a native identity')
    return usernames


def _prepare(entries, cursor, identity_schema):
    user_ids = sorted({user_id for entry in entries for user_id in entry['members']})
    for user_id in user_ids:
        identifier(user_id, maximum=225)
    bound = _bound_users(cursor, user_ids, identity_schema)
    resolved, unresolved, quarantined = [], set(), set()
    for entry in entries:
        missing = set(entry['members']) - bound.keys()
        if missing:
            unresolved.update(missing)
            quarantined.add(entry['external_id'])
        item = dict(entry)
        item['members'] = [bound[user_id] for user_id in entry['members'] if user_id in bound]
        resolved.append(item)
    return resolved, sorted(unresolved), quarantined


def _native_state(mapped, entries, cursor, native_schema):
    groups = qualified(native_schema, 'Group')
    by_id = {entry['external_id']: entry for entry in entries}
    members, protected = {}, {}
    for external_id, row in mapped.items():
        group_id = row['group_id']
        group = ccnet_api.get_group(group_id)
        if group is None:
            raise ValueError('mapped native group is missing')
        cursor.execute('SELECT parent_group_id FROM ' + groups + ' WHERE group_id=%s', (group_id,))
        native = cursor.fetchall()
        expected = by_id.get(external_id)
        if expected is not None:
            if row['parent_external_id'] != expected['parent_external_id']:
                raise ValueError('department hierarchy changed; manual migration required')
            parent = expected['parent_external_id']
            parent_id = mapped[parent]['group_id'] if parent else -1 if expected['subject_type'] == 'dept' else 0
            if native != ((parent_id,),):
                raise ValueError('mapped native group hierarchy differs')
        elif len(native) != 1:
            raise ValueError('mapped native group is missing')
        members[group_id] = [member.user_name for member in ccnet_api.get_group_members(group_id)]
        protected[group_id] = [group.creator_name]
    return members, protected


def _apply(plan, cursor, provider, owner, mapped):
    done, errors = {key: 0 for key in ('create', 'rename', 'add', 'remove', 'unmap')}, []
    ids = {key: row['group_id'] for key, row in mapped.items()}
    for entry in plan.create:
        key = entry['external_id']
        try:
            kind, namespace, external_id = _mapping(key, entry['subject_type'])
            parent = entry['parent_external_id']
            parent_id = ids[parent] if parent else -1 if kind == 'dept' else 0
            group_id = ccnet_api.create_group(entry['name'], owner, None, parent_id)
            now = int(time.time())
            cursor.execute('INSERT INTO cf_sso_group_map(provider,subject_type,namespace,external_id,group_id,name,parent_external_id,ctime,mtime) '
                           'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                           (provider, kind, namespace, external_id, group_id, entry['name'], parent, now, now))
            ids[key] = group_id
            done['create'] += 1
            for username in entry['members']:
                ccnet_api.group_add_member(group_id, owner, username)
                done['add'] += 1
        except Exception:
            logger.exception('Directory group creation failed for %s', key)
            errors.append('create ' + key)
    for entry in plan.rename:
        try:
            ccnet_api.set_group_name(entry['group_id'], entry['name'])
            cursor.execute('UPDATE cf_sso_group_map SET name=%s,mtime=%s WHERE provider=%s AND group_id=%s',
                           (entry['name'], int(time.time()), provider, entry['group_id']))
            done['rename'] += 1
        except Exception:
            logger.exception('Directory group rename failed')
            errors.append('rename ' + str(entry['group_id']))
    for operation in ('add', 'remove'):
        for entry in getattr(plan, operation):
            try:
                group_id, username = entry['group_id'], entry['identity']
                if operation == 'add':
                    ccnet_api.group_add_member(group_id, owner, username)
                else:
                    ccnet_api.group_remove_member(group_id, owner, username)
                    seafile_api.remove_group_repos_by_owner(group_id, username)
                done[operation] += 1
            except Exception:
                logger.exception('Directory membership %s failed', operation)
                errors.append(operation + ' ' + str(entry['group_id']))
    for entry in plan.unmap:
        kind, namespace, external_id = _mapping(entry['external_id'],
                                                'group' if entry['external_id'].startswith('role:') else 'dept')
        cursor.execute('DELETE FROM cf_sso_group_map WHERE provider=%s AND subject_type=%s AND namespace=%s AND external_id=%s AND group_id=%s',
                       (provider, kind, namespace, external_id, entry['group_id']))
        done['unmap'] += 1
    return done, errors


def sync():
    config = getattr(settings, 'CLOUDFILE_POLICY_CONFIG', None)
    owner = getattr(settings, 'CF_SSO_GROUP_OWNER', None)
    if not isinstance(config, dict) or not isinstance(owner, str) or not owner:
        raise ValueError('directory sync configuration is incomplete')
    identifier(owner, maximum=225)
    # v0.1 resolves the configured owner to an existing native user before any
    # group creation; keep that guard rather than inventing a service account.
    try:
        account = User.objects.get(email=owner)
        if not account.is_active:
            raise ValueError()
        owner = account.username
    except Exception:
        raise ValueError('configured directory group owner is unavailable') from None
    provider = config['provider']
    if provider != 'etech':
        raise ValueError('directory sync requires the eTech provider')
    source = trusted_https_url(config['directory_url']).rstrip('/') + '/groups'
    authorize = directory_authorization(config, getattr(settings, 'CLOUDFILE_DIRECTORY_AUTHORIZATION', None))
    client = HttpsJsonClient(ca_bundle=config.get('directory_ca_bundle'))
    try:
        payload = client.get(source, headers={'Authorization': authorize(), 'Accept': 'application/json'})
    finally:
        client.session.close()
    if not isinstance(payload.get('groups'), list):
        raise snapshot.SnapshotRejected('directory service returned no groups list')
    entries = snapshot.validate(payload['groups'])
    for entry in entries:
        _mapping(entry['external_id'], entry['subject_type'])
    connection = _database()
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK('cf.directory.sync',5)")
            locked = cursor.fetchone() == (1,)
            if not locked:
                raise ValueError('directory sync is busy')
            mapped = _read_mapped(cursor, provider)
            resolved, unresolved, quarantined = _prepare(entries, cursor, config['identity_schema'])
            members, protected = _native_state(mapped, resolved, cursor, config['native_schema'])
            # Preserve the v0.1 removal guard and its explicit operator override.
            ratio = getattr(settings, 'CF_SSO_MAX_REMOVAL_RATIO', reconcile.DEFAULT_MAX_REMOVAL_RATIO)
            ratio = None if ratio in ('', None) else float(ratio)
            plan = reconcile.build(resolved, mapped, members, protected=protected,
                                   quarantined=quarantined, max_removal_ratio=ratio)
            done, errors = _apply(plan, cursor, provider, owner, mapped)
            return dict(status='ERROR' if errors else 'OK', planned=plan.counts(), applied=done,
                        unresolved_user_ids=unresolved[:100], unresolved_count=len(unresolved),
                        quarantined_groups=sorted(quarantined)[:100], errors=errors[:20],
                        revision=payload.get('revision'))
    finally:
        if locked:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK('cf.directory.sync')")
            except Exception:
                logger.exception('Directory sync lock release failed')
        connection.close()
