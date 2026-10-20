"""Verified OIDC JIT using only CE User, Profile and SocialAuthUser facts.

This internal callback adapter does not authenticate an HTTP request. The caller
must verify issuer, audience, nonce and matching signed/UserInfo business UID.
Administrator preparation never calls this login authority.
"""
import json

from .errors import IdentityConflict
from .identity import text
from .oauth_identity import UIDBindingError, choose_uid_owner
from .schema import database_lock


class SQLJITProvisioner:
    def __init__(self, directory, identity):
        self.directory, self.identity = directory, identity

    def ensure(self, *, uid, provider, subject):
        from .etech_directory import verified_account
        uid, provider, subject = text(uid), text(provider, 32), text(subject, 255)
        identity, connection = self.identity, self.identity.connection
        # Serialize the provider subject before any account creation. A subject
        # already owned by a different UID cannot leave another new user behind.
        with database_lock(connection, 'identity:oauth:' + provider + ':' + subject):
            with connection.cursor() as cursor:
                cursor.execute('SELECT username,provider,uid FROM ' + identity.social +
                               ' WHERE provider=%s AND uid=%s', (provider, subject))
                bindings = cursor.fetchall()
                cursor.execute('SELECT user,login_id FROM ' + identity.profiles + ' WHERE login_id=%s', (uid,))
                profiles = cursor.fetchall()
            try:
                if bindings:
                    username = choose_uid_owner(uid, profiles, bindings, provider=provider, subject=subject)
                    identity.active(username, uid)
                login, account = verified_account(self.directory, uid)
                # Native RPC creates non-staff accounts. This primitive shares
                # UID/name locks and collision checks with staff preparation.
                username = identity.prepare(uid=uid, login_name=login, account=account)
                connection.begin()
                try:
                    identity.active(username, uid, locked=True)
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT username,provider,uid FROM ' + identity.social +
                                       ' WHERE provider=%s AND uid=%s FOR UPDATE', (provider, subject))
                        bindings = cursor.fetchall()
                        choose_uid_owner(uid, [(username, uid)], bindings, provider=provider, subject=subject)
                        if not bindings:
                            cursor.execute('INSERT INTO ' + identity.social +
                                '(username,provider,uid,extra_data) VALUES(%s,%s,%s,%s)',
                                (username, provider, subject, json.dumps({'userId': uid}, sort_keys=True)))
                    connection.commit()
                finally:
                    connection.rollback()
                return username
            except UIDBindingError:
                raise IdentityConflict('provider subject or UID conflict') from None
