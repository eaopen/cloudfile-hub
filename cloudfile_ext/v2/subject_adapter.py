"""Minimal, configuration-only selector for enterprise identity adapters.

A CE-only installation requires no enterprise Directory. A configured Etech
Directory preserves the deployed adapter by default; other enterprises must
explicitly provide BOTH their namespace and trusted subject refresh callback.
No UID format is an authentication or authorization signal.
"""


class InvalidSubjectAdapter(ValueError):
    pass


def selected_adapter(config):
    directory = getattr(config, 'CF_DIRECTORY_URL', '')
    provider = getattr(config, 'CF_ACL_PROVIDER', None)
    ensure = getattr(config, 'CF_ACL_SUBJECT_ENSURE', None)
    if provider is None and ensure is None:
        return ('etech', 'cloudfile_ext.v2.etech_directory.ensure_subject') if directory else None
    if (not isinstance(provider, str) or not provider or provider != provider.strip()
            or len(provider) > 128 or provider == 'native-local'
            or not isinstance(ensure, str) or not ensure or ensure != ensure.strip()
            or '.' not in ensure):
        raise InvalidSubjectAdapter('incomplete enterprise subject adapter')
    return provider, ensure
