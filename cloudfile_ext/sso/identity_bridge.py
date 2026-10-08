"""Resolve canonical EAP UIDs to CE native identities, in bounded DB batches.

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
    ambiguous = set()
    for start in range(0, len(logins), batch_size):
        for login, native_id in fetch(logins[start:start + batch_size]):
            if (not isinstance(login, str) or login not in wanted
                    or not isinstance(native_id, str) or not native_id):
                raise IdentityBridgeError('invalid Profile login binding')
            if login in result and result[login] != native_id:
                ambiguous.add(login)
            result[login] = native_id
    # A damaged row must not stop healthy employees; unresolved members cause
    # the caller to quarantine removals in their affected groups.
    for login in ambiguous:
        result.pop(login, None)
    return result


def resolve_eap_pairs(pairs, fetch=None, batch_size=256):
    """Scheme B: resolve only exact UID bindings; employee numbers never authorize.

    Historical employee login_id rows require a separately verified migration.
    Falling back here would let a recycled employee number inherit file access.
    """
    by_uid = {}
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
    existing = load_login_identities(list(by_uid), fetch=fetch, batch_size=batch_size)
    resolved = {}
    native_to_uid = {}
    ambiguous_native = set()
    for uid, employee in by_uid.items():
        native = existing.get(uid)
        # The system owner is independent of EAP employees and is never synced.
        if (employee and employee.lower() == 'cfadmin') or (
                native and native.lower() in ('cfadmin@etech.com', 'cfadmin@auth.local')):
            continue
        if native:
            if native in native_to_uid and native_to_uid[native] != uid:
                ambiguous_native.add(native)
            native_to_uid[native] = uid
            resolved[uid] = native
    return {uid: native for uid, native in resolved.items()
            if native not in ambiguous_native}
