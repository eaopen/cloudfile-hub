"""Resolve legacy native accounts through the authenticated business UID.

The EAP caller sends an employee technical identity. Existing OAuth bindings
may still use opaque native IDs; issuing their token must not rename accounts
or select an account by contact email.
"""
import re
from urllib.parse import quote

from .identity_bridge import load_login_identities


class TokenIdentityError(ValueError):
    pass


def resolve_employee_token(identity, source=None, fetch=None):
    if not isinstance(identity, str) or not re.fullmatch(r'[0-9]{1,32}@auth\.local', identity):
        raise TokenIdentityError('Unsupported employee technical identity')
    employee = identity.split('@', 1)[0]
    if source is None:
        from cloudfile_ext.registry import registry
        from .directory import active
        source = active(registry)
    if source is None or not hasattr(source, '_client'):
        raise TokenIdentityError('Authenticated directory is unavailable')
    client = source._client()
    # Only the scoped machine channel can establish the current employee->UID
    # pair. A legacy export/contact email is not proof of identity ownership.
    if client.auth_mode != 'v2':
        raise TokenIdentityError('Authenticated v2 directory is required')
    context = client.call('/users/by-login/%s/context' % quote(employee, safe=''), method='GET')
    uid = context.get('userId') if isinstance(context, dict) else None
    if (not isinstance(uid, str) or not uid.isascii() or not uid.isdigit()
            or context.get('status') != 'active'
            or not isinstance(context.get('attributes'), dict)
            or context['attributes'].get('employee_no') != employee):
        raise TokenIdentityError('Directory employee identity did not match')
    native = load_login_identities([uid], fetch=fetch).get(uid)
    if not native or native.lower() in ('cfadmin@etech.com', 'cfadmin@auth.local'):
        raise TokenIdentityError('Business UID has no unique employee account')
    return native
