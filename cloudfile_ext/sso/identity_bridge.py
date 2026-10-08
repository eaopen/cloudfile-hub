"""Resolve stable EAP employee logins to CE opaque identities, in bounded DB batches.

Uses Seahub's authoritative Profile.login_id unique mapping. No fallback to
contact_email: it is optional and may be shared or changed independently.
Missing profiles remain unresolved and the caller quarantines affected groups.
"""


class IdentityBridgeError(Exception):
    pass


def load_login_identities(logins, fetch=None, batch_size=256):
    """Return {login_id: native_identity} for provisioned profiles only.

    fetch(batch) may be injected in tests; production queries indexed Profile
    rows with one database roundtrip per batch, not per group-member occurrence.
    """
    if fetch is None:
        from seahub.profile.models import Profile
        fetch = lambda batch: Profile.objects.filter(
            login_id__in=batch).values_list('login_id', 'user')
    if not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError('batch_size must be positive')
    logins = sorted(set(v for v in logins if isinstance(v, str) and v.strip()))
    wanted = set(logins)
    result = {}
    for start in range(0, len(logins), batch_size):
        for login, native_id in fetch(logins[start:start + batch_size]):
            if (not isinstance(login, str) or login not in wanted
                    or not isinstance(native_id, str) or not native_id):
                raise IdentityBridgeError('invalid Profile login binding')
            if login in result and result[login] != native_id:
                raise IdentityBridgeError('ambiguous Profile login binding')
            result[login] = native_id
    return result


def resolve_eap_pairs(pairs, fetch=None, batch_size=256):
    """Resolve {user_id, employee_no} pairs to CE native identities, UID first.

    The identity stored by modern OIDC is EAP userId in Profile.login_id;
    older employees may have the employee number instead. Both may refer to
    the same CE user, but conflicting results are never silently merged.
    These are trusted, paired entries from a machine-authenticated directory,
    not separate arrays that can shift when one employee number is absent.
    No profile or user is created here.
    """
    by_uid = {}
    employee_owner = {}
    ambiguous = set()
    for pair in pairs:
        if not isinstance(pair, dict):
            raise IdentityBridgeError('invalid EAP identity record')
        uid, employee = pair.get('user_id'), pair.get('employee_no')
        if not isinstance(uid, str) or not uid.strip() or uid != uid.strip():
            raise IdentityBridgeError('invalid EAP userId')
        if employee is not None and (
                not isinstance(employee, str) or not employee.strip()
                or employee != employee.strip()):
            raise IdentityBridgeError('invalid EAP employee number')
        if uid in by_uid and by_uid[uid] != employee:
            raise IdentityBridgeError('EAP UID maps to two employee numbers')
        by_uid[uid] = employee
        if employee is not None:
            other = employee_owner.get(employee)
            if other is not None and other != uid:
                ambiguous.add(employee)
            else:
                employee_owner[employee] = uid
    # Canonical UID keys win. Employee fallback is allowed only when unique
    # and when it does not collide with another person's UID.
    key_owner = {uid: uid for uid in by_uid}
    for uid, employee in by_uid.items():
        if employee is None or employee in ambiguous:
            continue
        existing_owner = key_owner.get(employee)
        if existing_owner is not None and existing_owner != uid:
            ambiguous.add(employee)
        else:
            key_owner[employee] = uid
    existing = load_login_identities(list(key_owner), fetch=fetch, batch_size=batch_size)
    resolved = {}
    for uid, employee in by_uid.items():
        primary = existing.get(uid)
        fallback = existing.get(employee) if employee and employee not in ambiguous else None
        if primary and fallback and primary != fallback:
            raise IdentityBridgeError('UID and employee number resolve to different CE identities')
        if primary or fallback:
            resolved[uid] = primary or fallback
    # One CE account must never be assigned to two independent EAP UIDs.
    native_to_uid = {}
    for uid, native in resolved.items():
        if native in native_to_uid and native_to_uid[native] != uid:
            raise IdentityBridgeError('one CE identity maps to multiple EAP userIds')
        native_to_uid[native] = uid
    return resolved
