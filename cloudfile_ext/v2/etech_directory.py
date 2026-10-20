"""Trusted Etech Directory -> CE User/Group/GroupUser runtime; no shadow tables."""
from contextlib import contextmanager
from functools import lru_cache
from datetime import datetime, timezone
import json
import time
from urllib.parse import quote, urlsplit
from uuid import uuid4

import jwt
import pymysql
import redis
import requests
from django.conf import settings

from .errors import IdentityConflict, IdentityUnavailable, SubjectNotFound
from .identity import NativeIdentity, text
from cloudfile_ext.v2.account_names import account_username
from .memberships import GroupCatalog, Memberships, is_ready, readiness_key, validate_subject


class Directory:
    def __init__(self):
        self.base = getattr(settings, 'CF_DIRECTORY_URL', '').rstrip('/')
        parsed = urlsplit(self.base)
        self.secret = getattr(settings, 'CF_DIRECTORY_SECRET', '')
        self.key_id = getattr(settings, 'CF_DIRECTORY_KEY_ID', '')
        if (parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or
                parsed.password or parsed.query or parsed.fragment or not self.key_id or
                not isinstance(self.secret, str) or len(self.secret.encode()) < 32):
            raise IdentityUnavailable('trusted Directory connection required')

    def get(self, path):
        now = int(time.time())
        token = jwt.encode(dict(iss=getattr(settings, 'CF_DIRECTORY_ISSUER', 'cloudfile-sso'),
            aud=getattr(settings, 'CF_DIRECTORY_AUDIENCE', 'eap-directory'), sub='cloudfile',
            iat=now, exp=now+60, jti=str(uuid4()), scope='directory.read'), self.secret,
            algorithm='HS256', headers={'kid': self.key_id, 'typ': 'JWT'})
        try:
            # The destination and credential are server configuration only;
            # redirects must never forward the service token to another host.
            with requests.get(self.base + path, headers={'Authorization': 'Bearer '+token},
                              timeout=5, allow_redirects=False, stream=True) as reply:
                if reply.status_code == 404:
                    # The directory answers 404 SUBJECT_NOT_FOUND for an account
                    # that has no business subject (e.g. the system account whose
                    # login_id is 'cfadmin'). Report that as a fact, not as an
                    # outage: callers decide whether to fall back to native.
                    raw = bytearray()
                    try:
                        for chunk in reply.iter_content(4096):
                            raw.extend(chunk)
                            if len(raw) > 4096:
                                break
                        if json.loads(bytes(raw) or b'{}').get('code') == 'SUBJECT_NOT_FOUND':
                            raise SubjectNotFound('directory has no business subject for this account')
                    except SubjectNotFound:
                        raise
                    except Exception:
                        pass
                    raise ValueError()
                if reply.status_code != 200:
                    raise ValueError()
                raw = bytearray()
                for chunk in reply.iter_content(65536):
                    raw.extend(chunk)
                    if len(raw) > 4 * 1024 * 1024:
                        raise ValueError()
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValueError()
                return value
        except SubjectNotFound:
            raise
        except Exception:
            raise IdentityUnavailable('trusted Directory unavailable') from None

    def subject(self, uid):
        value = self.get('/users/' + quote(text(uid), safe='') + '/context')
        validate_subject(value, uid)
        return value

    def entities(self):
        value = self.get('/groups?view=entities')
        try:
            generated = datetime.fromisoformat(value['generated_at'].replace('Z', '+00:00'))
            if (value['contract_version'] != '2.0' or value['view'] != 'entities' or
                    generated.tzinfo is None or not -60 <= (datetime.now(timezone.utc)-generated).total_seconds() <= 60 or
                    not isinstance(value['groups'], list) or len(value['groups']) > 16384):
                raise ValueError()
            result = {}
            for item in value['groups']:
                kind = item['subject_type']
                namespace, external = text(item['namespace'], 128), text(item['external_id'])
                if (kind, namespace) not in (('org', 'directory'), ('role', 'role')):
                    raise ValueError()
                key = (kind, namespace, external)
                if key in result:
                    raise ValueError()
                result[key] = text(item['name'], 255)
            return result
        except (KeyError, TypeError, ValueError, IdentityConflict):
            raise IdentityUnavailable('invalid trusted Directory entities') from None


@contextmanager
def runtime():
    from seaserv import ccnet_api
    from seahub.utils.db_api import SeafileDB
    from seahub.utils.ccnet_db import get_ccnet_db_name
    directory = Directory()
    db = settings.DATABASES['default']
    # Projectors own transactions; never begin/commit on Django's request connection.
    conn = pymysql.connect(host=db.get('HOST') or 'localhost', port=int(db.get('PORT') or 3306),
        user=db['USER'], password=db['PASSWORD'], database=SeafileDB().db_name,
        charset='utf8mb4', autocommit=True, connect_timeout=5, read_timeout=10, write_timeout=10)
    cache = None
    try:
        account_schema = get_ccnet_db_name()
        def create_user(username):
            if ccnet_api.add_emailuser(username, uuid4().hex + uuid4().hex, 0, 1) != 0:
                raise IdentityUnavailable('native user creation failed')
        identity = NativeIdentity(conn, account_schema=account_schema, hub_schema=db['NAME'],
                                  issuer=directory.base, create_account=create_user)
        owner = getattr(settings, 'CF_DIRECTORY_GROUP_OWNER', '')
        def create_group(name):
            account = ccnet_api.get_emailuser(owner) if owner else None
            if account is None or not account.is_active or not account.is_staff:
                raise IdentityUnavailable('native group service owner required')
            return ccnet_api.create_group(name, owner)
        catalog = GroupCatalog(conn, account_schema=account_schema, provider='etech', create_group=create_group)
        cache = redis.Redis.from_url(redis_location(), socket_connect_timeout=5, socket_timeout=5)
        memberships = Memberships(conn, cache, identity, account_schema=account_schema, provider='etech',
            fetch=directory.subject, ttl=getattr(settings, 'CF_DIRECTORY_SUBJECT_TTL', 1800))
        yield directory, identity, catalog, memberships
    finally:
        if cache is not None:
            cache.close()
        conn.close()


def verified_account(directory, uid):
    """Shared Directory proof, independent of login/administrator authorization."""
    subject = directory.subject(uid)
    login, _ = validate_subject(subject, uid)
    if subject['status'] != 'active':
        raise IdentityUnavailable('Directory account disabled')
    # employee_no carries Etech account_, including nonnumeric accounts.
    # Only the trusted Directory supplies it; request aliases are not proof.
    account = subject['attributes'].get('employee_no')
    try:
        account_username(account)
    except ValueError:
        raise IdentityConflict('invalid Directory account') from None
    return login, account


def prepare_user(uid):
    with runtime() as (directory, identity, catalog, memberships):
        login, account = verified_account(directory, uid)
        return identity.prepare(uid=uid, login_name=login, account=account)


def provision_oidc_user(*, uid, provider, subject):
    """Internal callback only, after verified ID Token/UserInfo UID equality."""
    from .jit import SQLJITProvisioner
    with runtime() as (directory, identity, catalog, memberships):
        return SQLJITProvisioner(directory, identity).ensure(uid=uid, provider=provider, subject=subject)


def lookup_group(external):
    """Existing native mappings remain resolvable for revoke after entity deletion."""
    from django.db import connection
    from seahub.utils.db_api import SeafileDB
    from seahub.utils.ccnet_db import get_ccnet_db_name
    from .schema import identifier
    role = external.startswith('role:')
    key = ('role', 'role', external[5:]) if role else ('org', 'directory', external)
    files, accounts = identifier(SeafileDB().db_name), identifier(get_ccnet_db_name())
    with connection.cursor() as cursor:
        cursor.execute('SELECT m.subject_type,m.namespace,m.external_id,m.group_id,g.parent_group_id FROM ' +
            files + '.cf_sso_group_map m JOIN ' + accounts + '.`Group` g ON g.group_id=m.group_id '
            'WHERE m.provider=%s AND m.subject_type=%s AND m.namespace=%s AND m.external_id=%s',
            ('etech', *key))
        rows = cursor.fetchall()
    if not rows:
        return None
    if len(rows) != 1 or rows[0][:3] != key or rows[0][4] != 0:
        raise IdentityConflict('native group mapping changed')
    return rows[0][3]


def prepare_group(external):
    role = external.startswith('role:')
    key = ('role', 'role', external[5:]) if role else ('org', 'directory', external)
    with runtime() as (directory, identity, catalog, memberships):
        entities = directory.entities()
        if key not in entities:
            raise IdentityUnavailable('Directory entity unavailable')
        return catalog.ensure(*key, entities[key])


def redis_location():
    location = settings.CACHES.get('default', {}).get('LOCATION', '')
    if not isinstance(location, str) or not location.startswith(('redis://', 'rediss://', 'unix://')):
        raise IdentityUnavailable('shared native Redis connection required')
    return location


@lru_cache(maxsize=4)
def _shared_redis(location):
    # Process-wide pool; redis-py resets it after fork.
    return redis.Redis.from_url(location, socket_connect_timeout=5, socket_timeout=5)


def subject_ready(uid, username):
    """Read-only check of the marker Memberships.ensure() writes after commit.

    Uses pooled Redis and the request's Django connection instead of opening a
    dedicated MySQL/Redis pair and a database lock on every request. Repeats
    the binding/activity checks the locked path does on a hit. Any doubt
    returns False so the locked path decides, failing closed on its own.
    """
    from seaserv import ccnet_api
    from seahub.profile.models import Profile
    from seahub.utils.db_api import SeafileDB
    try:
        uid, username = text(uid), text(username, 255)
        database = SeafileDB().db_name
        ttl = getattr(settings, 'CF_DIRECTORY_SUBJECT_TTL', 1800)
        if not database or type(ttl) is not int or not 30 <= ttl <= 3600:
            return False
        key = readiness_key(database, 'etech', uid, username)
        if not is_ready(_shared_redis(redis_location()), key, uid, username, ttl):
            return False
        # NativeIdentity.active(): exact UID binding (user and login_id are
        # both unique) and an active native account.
        if list(Profile.objects.filter(user=username, login_id=uid).values_list('user', 'login_id')) != [(username, uid)]:
            return False
        account = ccnet_api.get_emailuser(username)
        # Match NativeIdentity.active() strictly: a case-insensitive CE lookup
        # must not turn a different stored native account into this UID's owner.
        return (account is not None and getattr(account, 'email', None) == username
                and getattr(account, 'is_active', None) == 1)
    except Exception:
        return False


def ensure_subject(uid, username):
    if subject_ready(uid, username):
        return
    with runtime() as (directory, identity, catalog, memberships):
        # Entity synchronization never expands users. Catalog is consulted only
        # after the subject TTL expires, including newly assigned departments.
        def fetch(current_uid):
            subject = directory.subject(current_uid)
            _, desired = validate_subject(subject, current_uid)
            if desired:
                entities = directory.entities()
                if not desired <= entities.keys():
                    raise IdentityUnavailable('Directory membership entity missing')
                for key in sorted(desired):
                    catalog.ensure(*key, entities[key])
            return subject
        memberships.fetch = fetch
        memberships.ensure(uid, username)


def sync_entity_catalog():
    """PowerJob/manual entity reconciliation, without any user/member writes.

    Etech remains the only organization truth. Preserve deleted/retired CE
    groups until a separate reviewed cleanup: they may own libraries.
    """
    from seaserv import ccnet_api
    with runtime() as (directory, identity, catalog, memberships):
        entities = directory.entities()  # Already validated /groups?view=entities.
        if not entities:
            raise IdentityUnavailable('empty entity catalog cannot be treated as a successful sync')
        renamed = unchanged = 0
        for key, name in sorted(entities.items()):
            group_id = catalog.ensure(*key, name)
            group = ccnet_api.get_group(group_id)
            if group is None:
                raise IdentityUnavailable('mapped native group missing')
            if group.group_name != name:
                ccnet_api.set_group_name(group_id, name)
                actual = ccnet_api.get_group(group_id)
                if actual is None or actual.group_name != name:
                    raise IdentityUnavailable('native group rename not confirmed')
                renamed += 1
            else:
                unchanged += 1
        return dict(status='OK', entities=len(entities), renamed=renamed,
                    unchanged=unchanged, membership_writes=0)
