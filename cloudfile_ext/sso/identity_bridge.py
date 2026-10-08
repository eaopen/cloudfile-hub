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
