"""Stable UID binding using CE's native account/Profile/OAuth facts only.

Ported invariants: exact provider/sub/UID matching and no email/name merging.
Trusted account naming affects creation only. No legacy worker is imported.
"""
from contextlib import ExitStack
import hashlib
import json
from uuid import uuid4

from .errors import IdentityConflict, IdentityUnavailable
from .schema import database_lock, identifier
from cloudfile_ext.v2.account_names import account_username


def text(value, maximum=225):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum or
            value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise IdentityConflict('invalid identity')
    return value


class NativeIdentity:
    def __init__(self, connection, *, account_schema, hub_schema, issuer, create_account=None):
        if not connection.get_autocommit():
            raise ValueError('dedicated autocommit connection required')
        self.connection = connection
        self.accounts = identifier(account_schema) + '.EmailUser'
        self.profiles = identifier(hub_schema) + '.profile_profile'
        self.social = identifier(hub_schema) + '.social_auth_usersocialauth'
        self.issuer = text(issuer, 2048)
        self.provider = 'cfv2_' + hashlib.sha256(issuer.encode()).hexdigest()[:26]
        self.create_account = create_account

    def active(self, username, uid, *, locked=False):
        if username.lower() in ('cfadmin@auth.local', 'cfadmin@etech.com'):
            raise IdentityConflict('reserved native account')
        suffix = ' FOR UPDATE' if locked else ''
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT user,login_id FROM ' + self.profiles + ' WHERE user=%s OR login_id=%s' + suffix, (username, uid))
            if cursor.fetchall() != ((username, uid),):
                raise IdentityConflict('native UID binding changed')
            cursor.execute('SELECT email,is_active FROM ' + self.accounts + ' WHERE email=%s' + suffix, (username,))
            if cursor.fetchall() != ((username, 1),):
                raise IdentityUnavailable('native account inactive')

    def prepare(self, *, uid, login_name, account=None):
        """Pre-create only a Directory-verified UID; never invent an OAuth sub."""
        uid, login_name = text(uid), text(login_name, 200)
        with database_lock(self.connection, 'identity:uid:' + uid):
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT user,login_id FROM ' + self.profiles + ' WHERE login_id=%s', (uid,))
                rows = cursor.fetchall()
            if rows:
                if len(rows) != 1 or rows[0][1] != uid:
                    raise IdentityConflict('ambiguous native UID binding')
                username = rows[0][0]
                self.active(username, uid)
                return username
            if self.create_account is None:
                raise IdentityUnavailable('native account creation unavailable')
            try:
                username = account_username(account) if account is not None else uuid4().hex + '@auth.local'
            except ValueError:
                raise IdentityConflict('invalid Directory account') from None
            # Serialize case variants too: CE account lookup is case insensitive.
            # Never adopt an unbound native account after a failed RPC/SQL attempt.
            with database_lock(self.connection, 'identity:account:' + username.lower()):
                with self.connection.cursor() as cursor:
                    cursor.execute('SELECT user,login_id FROM ' + self.profiles + ' WHERE user=%s', (username,))
                    if cursor.fetchall():
                        raise IdentityConflict('native account name already bound')
                    cursor.execute('SELECT email FROM ' + self.accounts + ' WHERE email=%s', (username,))
                    if cursor.fetchall():
                        raise IdentityConflict('native account name already exists')
                self.create_account(username)
                self.connection.begin()
                try:
                    with self.connection.cursor() as cursor:
                        cursor.execute('SELECT email,is_active FROM ' + self.accounts + ' WHERE email=%s FOR UPDATE', (username,))
                        if cursor.fetchall() != ((username, 1),):
                            raise IdentityUnavailable('native account creation failed')
                        # UID is the binding; the account only names a new user.
                        cursor.execute('INSERT INTO ' + self.profiles +
                            '(user,login_id,nickname,intro,lang_code,contact_email,is_manually_set_contact_email,institution,list_in_address_book) '
                            "VALUES(%s,%s,%s,'',NULL,NULL,0,'',0)", (username, uid, login_name[:64]))
                    self.connection.commit()
                finally:
                    self.connection.rollback()
            self.active(username, uid)
            return username

    def bind(self, *, subject, uid, login_name):
        # Both OAuth2 and OIDC callers must validate the external identity and
        # compare this exact UID with the trusted Directory before binding.
        subject, uid, login_name = text(subject, 255), text(uid), text(login_name, 200)
        metadata = {'issuer': self.issuer, 'external_user_id': uid}
        keys = sorted(['identity:uid:' + uid, 'identity:sub:' + self.provider + ':' + subject])
        with ExitStack() as stack:
            for key in keys:
                stack.enter_context(database_lock(self.connection, key))
            with self.connection.cursor() as cursor:
                cursor.execute('SELECT username,provider,uid,extra_data FROM ' + self.social +
                               ' WHERE provider=%s AND uid=%s', (self.provider, subject))
                rows = cursor.fetchall()
                if rows:
                    if len(rows) != 1:
                        raise IdentityConflict('ambiguous OAuth binding')
                    username, provider, saved_subject, raw = rows[0]
                    try:
                        saved = json.loads(raw)
                    except (TypeError, ValueError):
                        raise IdentityConflict('invalid OAuth UID binding') from None
                    if (provider != self.provider or saved_subject != subject or saved != metadata):
                        raise IdentityConflict('OAuth UID binding changed')
                    self.active(username, uid)
                    return username
                cursor.execute('SELECT user FROM ' + self.profiles + ' WHERE login_id=%s', (uid,))
                profiles = cursor.fetchall()
            if profiles:
                if len(profiles) != 1:
                    raise IdentityConflict('ambiguous native UID binding')
                username = profiles[0][0]
                # Reuse the same trusted UID's native account across login
                # methods. active() compares exact values, rejecting aliases
                # from the native case-insensitive login_id collation.
                self.active(username, uid)
            else:
                if self.create_account is None:
                    raise IdentityUnavailable('native account creation disabled')
                username = uuid4().hex + '@auth.local'
                # Native RPC owns account creation; failed SQL never publishes
                # a usable OAuth binding or group grant.
                self.create_account(username)
            self.connection.begin()
            try:
                with self.connection.cursor() as cursor:
                    cursor.execute('SELECT email,is_active FROM ' + self.accounts + ' WHERE email=%s FOR UPDATE', (username,))
                    if cursor.fetchall() != ((username, 1),):
                        raise IdentityUnavailable('native account creation failed')
                    if profiles:
                        self.active(username, uid, locked=True)
                    else:
                        cursor.execute('INSERT INTO ' + self.profiles +
                            '(user,login_id,nickname,intro,lang_code,contact_email,is_manually_set_contact_email,institution,list_in_address_book) '
                            "VALUES(%s,%s,%s,'',NULL,NULL,0,'',0)", (username, uid, login_name[:64]))
                    cursor.execute('INSERT INTO ' + self.social + '(username,provider,uid,extra_data) VALUES(%s,%s,%s,%s)',
                                   (username, self.provider, subject, json.dumps(metadata, sort_keys=True)))
                self.connection.commit()
            finally:
                self.connection.rollback()
            self.active(username, uid)
            return username
