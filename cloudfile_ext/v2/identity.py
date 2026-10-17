"""Stable UID binding using CE's native account/Profile/OAuth facts only.

Ported invariants: exact provider/sub/UID matching, no email/name merging,
and opaque native accounts. No legacy provisioning worker is imported.
"""
from contextlib import ExitStack
import hashlib
import json
from uuid import uuid4

from .errors import IdentityConflict, IdentityUnavailable
from .schema import database_lock, identifier


def text(value, maximum=225):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum or
            value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise IdentityConflict('invalid identity')
    return value


class NativeAccountBinding:
    """Exact native account/UID binding facts, without external proof state.

    Login binding and the subject projector share this check: an account is
    usable only while its native Profile still carries the exact stable UID and
    its native account is active. Splitting it keeps the projector independent
    of which login protocol created the binding.
    """

    def __init__(self, connection, *, account_schema, hub_schema):
        if not connection.get_autocommit():
            raise ValueError('dedicated autocommit connection required')
        self.connection = connection
        self.accounts = identifier(account_schema) + '.EmailUser'
        self.profiles = identifier(hub_schema) + '.profile_profile'

    def active(self, username, uid, *, locked=False):
        suffix = ' FOR UPDATE' if locked else ''
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT user,login_id FROM ' + self.profiles + ' WHERE user=%s OR login_id=%s' + suffix, (username, uid))
            if cursor.fetchall() != ((username, uid),):
                raise IdentityConflict('native UID binding changed')
            cursor.execute('SELECT email,is_active FROM ' + self.accounts + ' WHERE email=%s' + suffix, (username,))
            if cursor.fetchall() != ((username, 1),):
                raise IdentityUnavailable('native account inactive')


class NativeIdentity(NativeAccountBinding):
    def __init__(self, connection, *, account_schema, hub_schema, issuer, create_account=None):
        super().__init__(connection, account_schema=account_schema, hub_schema=hub_schema)
        self.social = identifier(hub_schema) + '.social_auth_usersocialauth'
        self.issuer = text(issuer, 2048)
        self.provider = 'cfv2_' + hashlib.sha256(issuer.encode()).hexdigest()[:26]
        self.create_account = create_account

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
