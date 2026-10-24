"""Low-frequency, startup-only trusted enterprise administrator reconciliation.

This feature does not hook authentication middleware, file operations, or
per-request Directory membership checks. Native cfadmin is never managed.
A complete, fresh Provider roster is required before any administrator write.
"""
from datetime import datetime, timezone

from .account_names import account_username
from .errors import IdentityUnavailable
from .schema import database_lock


ROLE = 'default_admin'
MAX_ADMINS = 32


def validated_roster(snapshot, *, now=None, required_account=''):
    """Validate the single complete authenticated Provider snapshot."""
    now = datetime.now(timezone.utc) if now is None else now
    try:
        if (not isinstance(snapshot, dict) or snapshot.get('contract_version') != '1.0'
                or snapshot.get('complete') is not True):
            raise ValueError()
        issued = datetime.fromisoformat(snapshot['generated_at'].replace('Z', '+00:00'))
        if issued.tzinfo is None or not -60 <= (now - issued).total_seconds() <= 60:
            raise ValueError()
        admins = snapshot['admins']
        # An empty/malformed source must never cause mass native revocation.
        if not isinstance(admins, list) or not 1 <= len(admins) <= MAX_ADMINS:
            raise ValueError()
        result = []
        uids = set()
        names = set()
        for item in admins:
            if not isinstance(item, dict):
                raise ValueError()
            uid, account = item['uid'], item['account']
            if (not isinstance(uid, str) or not uid or len(uid) > 225 or
                    uid.strip() != uid or not isinstance(account, str)):
                raise ValueError()
            name = account_username(account)
            if uid in uids or name in names:
                raise ValueError()
            uids.add(uid)
            names.add(name)
            result.append((uid, account))
        if required_account:
            if not isinstance(required_account, str) or account_username(required_account) not in names:
                raise ValueError()
        return tuple(result)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise IdentityUnavailable('invalid complete administrator roster') from None


def changes(current, wanted, *, managed_accounts=()):
    """Pure planning: default_admin in the managed CE namespace is Provider-owned.

    Only explicitly managed accounts may be automatically revoked. Native
    system_admin, cfadmin and other CE administrators remain untouched. A different explicit native administrator role or a
    staff user with no role must not be silently adopted.
    """
    managed = set(managed_accounts)
    if not all(isinstance(name, str) and name for name in managed):
        raise IdentityUnavailable('invalid managed administrator scope')
    add = set()
    remove = set()
    keep = set()
    for username, uid in wanted.items():
        state = current.get(username)
        if state is None:
            add.add(username)
        elif state == (uid, True, ROLE):
            keep.add(username)
        else:
            raise IdentityUnavailable('native administrator conflict')
    for username, (uid, staff, role) in current.items():
        if username not in wanted and username in managed and role == ROLE and uid:
            remove.add(username)
    return add, remove, keep


def sync_native_admins(identity, roster, *, managed_accounts=()):
    """Apply a whole authoritative admin roster once via existing CE facts.

    NativeIdentity.prepare() uses CE RPC to pre-create non-staff users with
    unguessable passwords; it reuses the exact UID owner when one exists.
    This does not start an SSO login. A single cross-schema MySQL transaction
    applies and reads back all staff/role changes. No cf_* table is created.
    """
    conn = identity.connection
    accounts = identity.accounts
    profiles = identity.profiles
    admin_roles = profiles.rsplit('.', 1)[0] + '.role_permissions_adminrole'
    # Pre-create only *verified, complete* roster identities; on failure none
    # can become admin, although a harmless nonstaff CE account may be staged.
    wanted = {}
    for uid, account in roster:
        username = identity.prepare(uid=uid, login_name=account, account=account)
        if username.lower().split('@', 1)[0] == 'cfadmin' or username in wanted:
            raise IdentityUnavailable('reserved or duplicate native administrator')
        wanted[username] = uid

    with database_lock(conn, 'provider-admin-startup:' + identity.provider):
        conn.begin()
        try:
            with conn.cursor() as cursor:
                # Native default_admin is reserved for this external provider
                # within the reviewed enterprise namespace. Native cfadmin and
                # separately administered system_admin identities are untouched.
                cursor.execute('SELECT a.email,p.login_id,e.is_staff,a.role FROM ' +
                               admin_roles + ' a LEFT JOIN ' + profiles + ' p ON p.user=a.email ' +
                               'LEFT JOIN ' + accounts + ' e ON e.email=a.email ' +
                               "WHERE a.role=%s FOR UPDATE", (ROLE,))
                current = {}
                for name, uid, staff, role in cursor.fetchall():
                    if (not name or name.lower().split('@', 1)[0] == 'cfadmin' or not uid):
                        continue
                    if staff not in (0, 1):
                        raise IdentityUnavailable('invalid existing native administrator')
                    current[name] = (uid, bool(staff), role)
                # A grant must not claim an existing implicit/other-role staff
                # administrator. First explicitly inspect all desired accounts.
                for name, uid in wanted.items():
                    cursor.execute('SELECT e.is_active,e.is_staff,p.login_id,a.role FROM ' +
                                   accounts + ' e JOIN ' + profiles + ' p ON p.user=e.email ' +
                                   'LEFT JOIN ' + admin_roles + ' a ON a.email=e.email ' +
                                   'WHERE e.email=%s FOR UPDATE', (name,))
                    rows = cursor.fetchall()
                    if len(rows) != 1 or rows[0][0] != 1 or rows[0][2] != uid:
                        raise IdentityUnavailable('native administrator UID/account mismatch')
                    _, staff, _, role = rows[0]
                    if staff not in (0, 1):
                        raise IdentityUnavailable('invalid staff marker')
                    if role == ROLE and staff == 1:
                        current[name] = (uid, True, ROLE)
                    elif role is not None or staff == 1:
                        raise IdentityUnavailable('existing manual administrator cannot be adopted')
                add, remove, keep = changes(current, wanted, managed_accounts=managed_accounts)
                for name in sorted(add):
                    cursor.execute('INSERT INTO ' + admin_roles +
                                   ' (email,role) VALUES(%s,%s)', (name, ROLE))
                    cursor.execute('UPDATE ' + accounts +
                                   ' SET is_staff=1 WHERE email=%s AND is_active=1 AND is_staff=0', (name,))
                    if cursor.rowcount != 1:
                        raise IdentityUnavailable('native administrator grant conflict')
                for name in sorted(remove):
                    if current[name][1]:
                        cursor.execute('UPDATE ' + accounts +
                                       ' SET is_staff=0 WHERE email=%s AND is_staff=1', (name,))
                        if cursor.rowcount != 1:
                            raise IdentityUnavailable('native administrator revoke conflict')
                    cursor.execute('DELETE FROM ' + admin_roles +
                                   ' WHERE email=%s AND role=%s', (name, ROLE))
                    if cursor.rowcount != 1:
                        raise IdentityUnavailable('native role removal conflict')
                    cursor.execute('SELECT is_staff FROM ' + accounts +
                                   ' WHERE email=%s', (name,))
                    if cursor.fetchall() != ((0,),):
                        raise IdentityUnavailable('native administrator revoke readback mismatch')
                for name, uid in wanted.items():
                    cursor.execute('SELECT e.is_staff,p.login_id,a.role FROM ' +
                                   accounts + ' e JOIN ' + profiles + ' p ON p.user=e.email ' +
                                   'JOIN ' + admin_roles + ' a ON a.email=e.email ' +
                                   'WHERE e.email=%s', (name,))
                    if cursor.fetchall() != ((1, uid, ROLE),):
                        raise IdentityUnavailable('native administrator readback mismatch')
            conn.commit()
            return dict(status='APPLIED', added=len(add), removed=len(remove), kept=len(keep))
        except BaseException:
            conn.rollback()
            raise
