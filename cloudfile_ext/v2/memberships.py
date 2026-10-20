"""Current-user TTL projection into native GroupUser, without task/outbox state."""
from datetime import datetime, timezone
import hashlib
import json

from .errors import IdentityConflict, IdentityUnavailable
from .identity import text
from .schema import database_lock, identifier


def validate_subject(value, uid, *, now=None):
    now = datetime.now(timezone.utc) if now is None else now
    try:
        if not isinstance(value, dict) or value['userId'] != uid or value['status'] not in ('active', 'disabled'):
            raise ValueError()
        generated = datetime.fromisoformat(value['generated_at'].replace('Z', '+00:00'))
        if generated.tzinfo is None or not -60 <= (now - generated).total_seconds() <= 60:
            raise ValueError()
        attrs = value['attributes']
        if not isinstance(attrs, dict):
            raise ValueError()
        login = attrs.get('login_name', attrs.get('employee_no'))
        if attrs.get('login_name', login) != attrs.get('employee_no', login):
            raise ValueError()
        # Account metadata names new users only. Existing UID owners and their
        # memberships remain valid when that metadata is missing or noncanonical.
        if login is not None and not isinstance(login, str):
            raise ValueError()
        text(value['etag'])
        desired = set()
        for field, kind in (('organizations', 'org'), ('organization_ancestors', 'org'), ('roles', 'role')):
            items = value[field]
            if not isinstance(items, list) or len(items) > 4096:
                raise ValueError()
            for item in items:
                key = (kind, text(item['namespace'], 128), text(item['external_id']))
                if key in desired:
                    raise ValueError()
                desired.add(key)
        if value['status'] == 'disabled' and desired:
            raise ValueError()
        return login, desired
    except (KeyError, TypeError, AttributeError, ValueError, IdentityConflict):
        raise IdentityUnavailable('invalid current Directory response') from None


def readiness_key(database, provider, uid, username):
    return 'cfv2:subject:' + hashlib.sha256(json.dumps([database, provider, uid, username]).encode()).hexdigest()


def is_ready(redis, key, uid, username, ttl):
    """True only for this exact subject's marker, written after a committed projection."""
    cached, remaining = redis.eval(
        "local v=redis.call('GET',KEYS[1]); return {v or '',redis.call('PTTL',KEYS[1])}", 1, key)
    return bool(cached) and 0 < remaining <= ttl * 1000 and json.loads(cached) == {'uid': uid, 'username': username}


class Memberships:
    def __init__(self, connection, redis, identity, *, account_schema, provider, fetch, ttl=1800):
        if not connection.get_autocommit() or not callable(fetch) or type(ttl) is not int or not 30 <= ttl <= 3600:
            raise ValueError('dedicated connection, trusted Directory and bounded TTL required')
        self.connection, self.redis, self.identity = connection, redis, identity
        self.provider, self.fetch, self.ttl = text(provider, 32), fetch, ttl
        self.groups = identifier(account_schema) + '.`Group`'
        self.members = identifier(account_schema) + '.GroupUser'

    def _key(self, uid, username):
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT DATABASE()')
            database = cursor.fetchone()[0]
        return readiness_key(database, self.provider, uid, username)

    def ensure(self, uid, username, *, force=False, subject=None):
        uid, username = text(uid), text(username, 255)
        key = self._key(uid, username)
        try:
            # Network fetches serialize only this user. Catalog mutation and
            # SQL publication share the much shorter provider critical section.
            with database_lock(self.connection, 'subject:' + self.provider + ':' + uid):
                self.identity.active(username, uid)
                if not force and subject is None and is_ready(self.redis, key, uid, username, self.ttl):
                    return
                self.redis.delete(key)
                current = self.fetch(uid) if subject is None else subject
                _, desired = validate_subject(current, uid)
                with database_lock(self.connection, 'groups:' + self.provider):
                    self._project(uid, username, desired)
                    if current['status'] != 'active':
                        raise IdentityUnavailable('Directory account disabled')
                    # Readiness is written only after SQL commit. Cache failure
                    # refuses this request; old GroupUser is never freshness proof.
                    self.redis.set(key, json.dumps({'uid': uid, 'username': username}), ex=self.ttl)
        except IdentityUnavailable:
            raise
        except Exception:
            raise IdentityUnavailable('subject projection unavailable') from None

    def _project(self, uid, username, desired):
        self.connection.begin()
        try:
            self.identity.active(username, uid, locked=True)
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT subject_type,namespace,external_id,group_id FROM cf_sso_group_map WHERE provider=%s ORDER BY group_id FOR UPDATE', (self.provider,))
                rows = cursor.fetchall()
                if len(rows) > 16384:
                    raise IdentityUnavailable('group catalog too large')
                mappings = {row[:3]: row[3] for row in rows}
                owned = set(mappings.values())
                if len(owned) != len(rows) or not desired <= mappings.keys():
                    raise IdentityUnavailable('required native group mapping missing')
                # Flat native groups avoid implicit CE hierarchy grants. The
                # trusted Directory supplies effective ancestors explicitly.
                for group in sorted(owned):
                    cursor.execute('SELECT group_id,parent_group_id FROM ' + self.groups + ' WHERE group_id=%s FOR UPDATE', (group,))
                    if cursor.fetchall() != ((group, 0),):
                        raise IdentityUnavailable('native mapped group changed')
                cursor.execute('SELECT group_id,is_staff FROM ' + self.members + ' WHERE user_name=%s ORDER BY group_id FOR UPDATE', (username,))
                members = cursor.fetchall()
                if any(group in owned and staff != 0 for group, staff in members):
                    raise IdentityConflict('native group administrator requires review')
                existing = {group for group, _ in members}
                required = {mappings[item] for item in desired}
                for group in sorted((existing & owned) - required):
                    cursor.execute('DELETE FROM ' + self.members + ' WHERE group_id=%s AND user_name=%s AND is_staff=0', (group, username))
                for group in sorted(required - existing):
                    cursor.execute('INSERT INTO ' + self.members + '(group_id,user_name,is_staff) VALUES(%s,%s,0)', (group, username))
                cursor.execute('SELECT group_id,is_staff FROM ' + self.members + ' WHERE user_name=%s ORDER BY group_id FOR UPDATE', (username,))
                actual = cursor.fetchall()
                if ({group for group, _ in actual} & owned) != required or any(group in owned and staff != 0 for group, staff in actual):
                    raise IdentityUnavailable('native membership readback failed')
            self.connection.commit()
        finally:
            self.connection.rollback()


class GroupCatalog:
    """Bind freshly created native groups; never adopt/remap/delete manual groups."""
    def __init__(self, connection, *, account_schema, provider, create_group):
        self.connection, self.create_group = connection, create_group
        self.groups = identifier(account_schema) + '.`Group`'
        self.provider = text(provider, 32)

    def ensure(self, kind, namespace, external_id, name):
        if kind not in ('org', 'role'):
            raise ValueError('unsupported external group kind')
        namespace, external_id, name = text(namespace, 128), text(external_id), text(name, 255)
        key = (self.provider, kind, namespace, external_id)
        with database_lock(self.connection, 'groups:' + self.provider):
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT provider,subject_type,namespace,external_id,group_id FROM cf_sso_group_map '
                               'WHERE provider=%s AND subject_type=%s AND namespace=%s AND external_id=%s', key)
                rows = cursor.fetchall()
                if rows:
                    if len(rows) != 1 or rows[0][:4] != key:
                        raise IdentityConflict('external group collation alias')
                    group = rows[0][4]
                else:
                    # RPC owns the native Group entity. No name-based matching.
                    group = self.create_group(name)
                    if type(group) is not int or not 1 <= group <= 2147483647:
                        raise IdentityUnavailable('native group creation failed')
                cursor.execute('SELECT group_id,parent_group_id FROM ' + self.groups + ' WHERE group_id=%s', (group,))
                native = cursor.fetchall()
                if (len(native) != 1 or native[0][0] != group or
                        (kind == 'role' and native[0][1] != 0) or
                        (kind == 'org' and (type(native[0][1]) is not int or native[0][1] < -1))):
                    raise IdentityUnavailable('mapped group unavailable')
                if not rows:
                    cursor.execute('INSERT INTO cf_sso_group_map(provider,subject_type,namespace,external_id,group_id) VALUES(%s,%s,%s,%s,%s)', (*key, group))
                return group
