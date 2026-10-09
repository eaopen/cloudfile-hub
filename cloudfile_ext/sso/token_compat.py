"""Opt-in legacy EAP transport names, never contact-email identity inference."""
import re


def normalize_token_identity(identity, legacy_domain=''):
    # Only the authenticated administrator token endpoint consumes this adapter.
    # Exact operator-configured domain + employee syntax avoids email collisions
    # and preserves the reviewed alias / current EAP UID proof after conversion.
    if not legacy_domain:
        return identity, False
    if not isinstance(legacy_domain, str) or not re.fullmatch(r'[a-z0-9.-]+', legacy_domain):
        raise ValueError('Invalid legacy token identity domain')
    if not isinstance(identity, str) or not identity.endswith('@' + legacy_domain):
        return identity, False
    account = identity[:-len(legacy_domain) - 1]
    if not re.fullmatch(r'(?:[0-9]{1,32}|admin)', account):
        raise ValueError('Unsupported legacy token account')
    return account + '@auth.local', True
