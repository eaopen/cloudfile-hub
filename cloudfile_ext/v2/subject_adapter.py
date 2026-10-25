"""Minimal selector for enterprise identity adapters.

A CE-only installation requires no enterprise Directory. Explicit provider
settings always win. Otherwise a configured, machine-authenticated Directory
may declare a stable namespace in its existing entities snapshot. Providers
without that declaration retain the generic ``external`` default. The trusted
snapshot is read once per worker, never on a warm ACL permission path. Custom
adapters continue to require an explicit provider and refresh callback.
No UID format is an authentication or authorization signal.
"""


import threading
import time

from .errors import IdentityUnavailable


DEFAULT_PROVIDER = 'external'
PREFERRED_PROVIDER_SETTING = 'CF_DIRECTORY_PROVIDER'
LEGACY_PROVIDER_SETTING = 'CF_ACL_PROVIDER'
BUILTIN_ENSURE = None  # CE Profile + GroupUser are read-only on permission paths
LEGACY_ENSURE = 'cloudfile_ext.v2.directory_adapter.ensure_subject'


class InvalidSubjectAdapter(ValueError):
    pass


def _namespace_from_entities(facts):
    """Validate the existing trusted entities contract before accepting a provider."""
    from .provider_contract import validated_entities

    validated_entities(facts)
    declared = facts.get('provider')
    if declared is None:  # older/generic Directory contract
        return None
    declared = _checked_provider(declared)
    if len(declared) > 32:  # cf_dir_acl.provider / cf_sso_group_map.provider
        raise InvalidSubjectAdapter('Directory provider namespace too long')
    return declared


# Process-local namespace is stable for the lifetime of a Hub worker.
# A failed first fetch must not trigger a 5-second HTTP request for every ACL.
# Retry failed fetches after a fixed, small cool-down; no external cache/scheduler.
_NAMESPACE_UNSET = object()
_NAMESPACE_LOCK = threading.Lock()
_NAMESPACE_RESOLVED = {}
_NAMESPACE_RETRY_AFTER = {}


def _trusted_directory_namespace(url, key_id, secret, issuer, audience):
    """Read once from the trusted Directory, throttling only unavailable results."""
    from .directory_adapter import Directory

    key = (url, key_id, secret, issuer, audience)
    resolved = _NAMESPACE_RESOLVED.get(key, _NAMESPACE_UNSET)
    if resolved is not _NAMESPACE_UNSET:
        return resolved

    if time.monotonic() < _NAMESPACE_RETRY_AFTER.get(key, 0):
        raise IdentityUnavailable('trusted Directory namespace temporarily unavailable')

    # A single cold request fetches the catalog. Concurrent requests reuse
    # its result (or return a bounded 503), not a burst of Directory HTTP.
    with _NAMESPACE_LOCK:
        resolved = _NAMESPACE_RESOLVED.get(key, _NAMESPACE_UNSET)
        if resolved is not _NAMESPACE_UNSET:
            return resolved
        if time.monotonic() < _NAMESPACE_RETRY_AFTER.get(key, 0):
            raise IdentityUnavailable('trusted Directory namespace temporarily unavailable')
        try:
            resolved = _namespace_from_entities(Directory().get('/groups?view=entities'))
        except (IdentityUnavailable, InvalidSubjectAdapter):
            _NAMESPACE_RETRY_AFTER[key] = time.monotonic() + 30
            raise
        _NAMESPACE_RESOLVED[key] = resolved
        _NAMESPACE_RETRY_AFTER.pop(key, None)
        return resolved


def provider_name(config, default=DEFAULT_PROVIDER):
    """One stable namespace for ACL, group projection and effective permissions.

    Explicit settings win; the verified Directory declaration is considered only
    when no provider was configured. Persisted namespaces never follow an
    unauthenticated request, UserInfo field or user-controlled account name.
    """
    for setting in (PREFERRED_PROVIDER_SETTING, LEGACY_PROVIDER_SETTING):
        value = getattr(config, setting, None)
        if value is not None:
            return _checked_provider(value)

    url = getattr(config, 'CF_DIRECTORY_URL', '')
    key_id = getattr(config, 'CF_DIRECTORY_KEY_ID', '')
    secret = getattr(config, 'CF_DIRECTORY_SECRET', '')
    if url and key_id and secret:
        declared = _trusted_directory_namespace(
            url, key_id, secret,
            getattr(config, 'CF_DIRECTORY_ISSUER', 'cloudfile-sso'),
            getattr(config, 'CF_DIRECTORY_AUDIENCE', 'eap-directory'))
        if declared is not None:
            return declared
    return _checked_provider(default)


def _checked_provider(provider):
    if (not isinstance(provider, str) or not provider or provider != provider.strip()
            or len(provider) > 128 or provider == 'native-local'):
        raise InvalidSubjectAdapter('invalid enterprise subject namespace')
    return provider


def selected_adapter(config):
    directory = getattr(config, 'CF_DIRECTORY_URL', '')
    provider = getattr(config, PREFERRED_PROVIDER_SETTING, None)
    if provider is None:
        provider = getattr(config, LEGACY_PROVIDER_SETTING, None)
    ensure = getattr(config, 'CF_ACL_SUBJECT_ENSURE', None)
    if ensure is None:
        if not directory:
            if provider is not None:
                raise InvalidSubjectAdapter('provider configured without a Directory URL')
            return None
        return provider_name(config), BUILTIN_ENSURE
    if (not isinstance(ensure, str) or not ensure or ensure != ensure.strip()
            or '.' not in ensure):
        raise InvalidSubjectAdapter('incomplete enterprise subject adapter')
    if provider is None:
        raise InvalidSubjectAdapter('incomplete enterprise subject adapter')
    return _checked_provider(provider), None if ensure == LEGACY_ENSURE else ensure


# Only the built-in local CE administrator may bypass the configured enterprise
# subject adapter. A business profile containing the string 'cfadmin' is not
# sufficient proof that its CE account is the reserved native administrator.
_NATIVE_ADMINS = frozenset(('cfadmin@auth.local',))


def native_admin_identity(uid, username):
    return uid == 'cfadmin' and username in _NATIVE_ADMINS


def reserved_identity_conflict(uid, username):
    return (uid == 'cfadmin' or username in _NATIVE_ADMINS) and not native_admin_identity(uid, username)
