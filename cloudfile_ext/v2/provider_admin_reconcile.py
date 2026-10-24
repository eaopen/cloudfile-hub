"""Opt-in enterprise CE administrator projection; no shadow authority table.

This is deliberately NOT registered on any request or login path yet.
The caller must supply a trusted server-side Directory fetch (not request JSON)
and explicitly opt in after reviewing existing native administrators.
A separate admin-request gate must enforce freshness before deployment.

The current deployment's Directory owns its verified external identities.
Native cfadmin and native admins without an explicit default_admin role
remain outside this reconciler's mutation domain.
"""
from dataclasses import dataclass

from .errors import IdentityUnavailable
from .provider_admin import trusted_super_admin
from .schema import database_lock, identifier


class AdminOwnershipConflict(RuntimeError):
    """Avoid modifying an existing native administrator with unknown ownership."""


@dataclass(frozen=True)
class AdminNativeState:
    is_staff: bool
    role: str | None


def transition(state, desired):
    """Return a safe action for this provider-managed external identity.

    The operator must audit any pre-existing CE default_admin before opting
    into an enterprise-owned namespace. We never adopt a staff account that
    has the implicit system_admin role or any distinct explicit admin role.
    """
    if type(desired) is not bool or not isinstance(state, AdminNativeState):
        raise AdminOwnershipConflict('invalid admin transition')
    if type(state.is_staff) is not bool or (state.role is not None and
            (not isinstance(state.role, str) or not state.role)):
        raise AdminOwnershipConflict('invalid native admin state')
    if state.is_staff:
        if state.role == 'default_admin':
            return 'retain' if desired else 'revoke'
        if desired:
            raise AdminOwnershipConflict('pre-existing native administrator not provider-owned')
        return 'unmanaged'
    if state.role is not None:
        # An inactive/staged admin role is not proof of provider ownership.
        if desired:
            raise AdminOwnershipConflict('pre-existing native admin role not provider-owned')
        return 'unmanaged'
    return 'grant' if desired else 'unchanged'


def _reserved_native(username):
    return (not isinstance(username, str) or not username or
            username.split('@', 1)[0].lower() == 'cfadmin')


def reconcile_native_admin(identity, uid, username, *, fetch_subject, enabled=False):
    """Atomically reconcile native CE staff+AdminRole for one verified UID.

    Uses the existing MySQL schemas via the NativeIdentity dedicated
    autocommit connection, with a user-scoped advisory lock and a single
    cross-schema transaction. The Directory HTTP call occurs *before* locks.
    No group, repository, profile, OAuth or content authorization is changed.
    """
    if enabled is not True:
        raise AdminOwnershipConflict('enterprise administrator synchronization disabled')
    if _reserved_native(username) or not isinstance(uid, str) or not uid:
        raise AdminOwnershipConflict('native administrator is reserved')
    if not callable(fetch_subject):
        raise AdminOwnershipConflict('trusted server-side Directory required')

    subject = fetch_subject(uid)
    desired = trusted_super_admin(subject, uid, require_claim=True)
    # Reuse the strict identity binding already used by Provider/JIT.
    identity.active(username, uid)
    conn = identity.connection
    native_table = identity.accounts
    role_table = identifier(identity.hub_schema) + '.role_permissions_adminrole' if hasattr(identity, 'hub_schema') else None
    if not role_table:
        # NativeIdentity carries profiles and social table identifiers in the
        # Seahub schema; obtain that schema from its reviewed profile path.
        profile_prefix = identity.profiles.rsplit('.', 1)[0]
        role_table = profile_prefix + '.role_permissions_adminrole'

    with database_lock(conn, 'identity:admin:' + uid):
        identity.active(username, uid)
        conn.begin()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    'SELECT user,login_id FROM ' + identity.profiles +
                    ' WHERE user=%s OR login_id=%s FOR UPDATE', (username, uid))
                if cursor.fetchall() != ((username, uid),):
                    raise AdminOwnershipConflict('native UID binding changed')
                cursor.execute(
                    'SELECT email,is_active,is_staff FROM ' + native_table +
                    ' WHERE email=%s FOR UPDATE', (username,))
                account = cursor.fetchall()
                if (len(account) != 1 or account[0][:2] != (username, 1)
                        or account[0][2] not in (0, 1)):
                    raise IdentityUnavailable('native account unavailable')
                cursor.execute(
                    'SELECT role FROM ' + role_table + ' WHERE email=%s FOR UPDATE',
                    (username,))
                role_rows = cursor.fetchall()
                if len(role_rows) > 1:
                    raise AdminOwnershipConflict('ambiguous administrator role')
                state = AdminNativeState(bool(account[0][2]),
                                         role_rows[0][0] if role_rows else None)
                action = transition(state, desired)
                if action == 'grant':
                    cursor.execute('INSERT INTO ' + role_table +
                                   ' (email,role) VALUES(%s,%s)',
                                   (username, 'default_admin'))
                    cursor.execute('UPDATE ' + native_table +
                                   ' SET is_staff=1 WHERE email=%s AND is_active=1 AND is_staff=0',
                                   (username,))
                    if cursor.rowcount != 1:
                        raise AdminOwnershipConflict('native administrator grant raced')
                elif action == 'revoke':
                    cursor.execute('UPDATE ' + native_table +
                                   ' SET is_staff=0 WHERE email=%s AND is_active=1 AND is_staff=1',
                                   (username,))
                    if cursor.rowcount != 1:
                        raise AdminOwnershipConflict('native administrator revoke raced')
                    cursor.execute('DELETE FROM ' + role_table +
                                   ' WHERE email=%s AND role=%s',
                                   (username, 'default_admin'))
                    if cursor.rowcount != 1:
                        raise AdminOwnershipConflict('administrator role revoke raced')
                cursor.execute('SELECT email,is_staff FROM ' + native_table +
                               ' WHERE email=%s', (username,))
                after_native = cursor.fetchall()
                cursor.execute('SELECT role FROM ' + role_table +
                               ' WHERE email=%s', (username,))
                after_role = cursor.fetchall()
                expected_staff = state.is_staff
                expected_role = state.role
                if action == 'grant':
                    expected_staff, expected_role = True, 'default_admin'
                elif action == 'revoke':
                    expected_staff, expected_role = False, None
                if (after_native != ((username, int(expected_staff)),) or
                        after_role != (() if expected_role is None else ((expected_role,),))):
                    raise AdminOwnershipConflict('native administrator readback mismatch')
            conn.commit()
            return action
        except BaseException:
            conn.rollback()
            raise
