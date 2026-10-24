"""Trusted enterprise provider administrator *input* contract.

This parser does not grant CloudFile administrator privileges. A separate,
reviewed native reconciliation and admin-request gate must apply its decision.
Never infer administrator privileges from a username, Org/Role group name, or
OAuth UserInfo supplied by a browser.
"""

from .errors import IdentityUnavailable


def trusted_super_admin(subject, uid, *, require_claim=False):
    """Validate the authenticated Directory's UID/status and boolean claim.

    Older, non-admin-synchronizing providers may omit the optional claim.
    A deployment managing CE administrator roles must set require_claim=True
    so an old/partial response cannot silently preserve stale privileges.
    """
    if (not isinstance(subject, dict)
            or not isinstance(uid, str) or not uid
            or subject.get('userId') != uid
            or subject.get('status') not in ('active', 'disabled')):
        raise IdentityUnavailable('invalid trusted administrator subject')

    if 'super_admin' not in subject:
        if require_claim:
            raise IdentityUnavailable('administrator authority claim unavailable')
        return False

    is_admin = subject['super_admin']
    if type(is_admin) is not bool:
        raise IdentityUnavailable('administrator authority claim must be boolean')
    if is_admin and subject['status'] != 'active':
        raise IdentityUnavailable('inactive subject cannot hold administrator role')
    return is_admin
