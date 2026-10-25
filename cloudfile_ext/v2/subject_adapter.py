"""Minimal, configuration-only selector for enterprise identity adapters.

A CE-only installation requires no enterprise Directory. A configured
enterprise Directory uses the built-in generic adapter; its namespace is
CF_ACL_PROVIDER (default ``external``), so consumers keep their own provider
identifier. Custom adapters must explicitly provide BOTH their namespace and
trusted subject refresh callback. No UID format is an authentication or
authorization signal.
"""


DEFAULT_PROVIDER = 'external'
BUILTIN_ENSURE = 'cloudfile_ext.v2.directory_adapter.ensure_subject'


class InvalidSubjectAdapter(ValueError):
    pass


def provider_name(config, default=DEFAULT_PROVIDER):
    """Namespace identifier for rules, group maps and identity keys."""
    value = getattr(config, 'CF_ACL_PROVIDER', None)
    return default if value is None else value


def _checked_provider(provider):
    if (not isinstance(provider, str) or not provider or provider != provider.strip()
            or len(provider) > 128 or provider == 'native-local'):
        raise InvalidSubjectAdapter('invalid enterprise subject namespace')
    return provider


def selected_adapter(config):
    directory = getattr(config, 'CF_DIRECTORY_URL', '')
    provider = getattr(config, 'CF_ACL_PROVIDER', None)
    ensure = getattr(config, 'CF_ACL_SUBJECT_ENSURE', None)
    if ensure is None:
        if not directory:
            if provider is not None:
                raise InvalidSubjectAdapter('provider configured without a Directory URL')
            return None
        return _checked_provider(provider_name(config)), BUILTIN_ENSURE
    if (not isinstance(ensure, str) or not ensure or ensure != ensure.strip()
            or '.' not in ensure):
        raise InvalidSubjectAdapter('incomplete enterprise subject adapter')
    if provider is None:
        raise InvalidSubjectAdapter('incomplete enterprise subject adapter')
    return _checked_provider(provider), ensure


# Only the built-in local CE administrator may bypass the configured enterprise
# subject adapter. A business profile containing the string 'cfadmin' is not
# sufficient proof that its CE account is the reserved native administrator.
_NATIVE_ADMINS = frozenset(('cfadmin@auth.local',))


def native_admin_identity(uid, username):
    return uid == 'cfadmin' and username in _NATIVE_ADMINS


def reserved_identity_conflict(uid, username):
    return (uid == 'cfadmin' or username in _NATIVE_ADMINS) and not native_admin_identity(uid, username)
