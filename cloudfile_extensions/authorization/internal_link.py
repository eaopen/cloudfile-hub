"""Resolve an existing Seafile Internal Link with current CloudFile ACL.

Smart links contain only the native FileUUIDMap locator. No bearer token,
authorization row or virtual repository is created. In a deployed v0.9 scoped
runtime, use the same directory-address authority as ordinary browsing;
otherwise retain stock Seafile CE handling without widening any access.
"""
from uuid import uuid4


def scoped_directory_address(request, repo_id, path):
    """Return (root_path, initial_path, permission), or None for stock CE.

    A configured policy runtime must fail closed, never downgrade to ordinary
    repository permissions when subject/ACL verification is unavailable.
    """
    from django.conf import settings
    reference = {'repo_id': repo_id, 'path': path, 'kind': 'dir'}
    value = {'reference': reference}
    if getattr(settings, 'CLOUDFILE_AUTHORIZATION_ENABLED', False):
        from .gunicorn import directory_service
        with directory_service(request, str(uuid4())) as service:
            return service.resolve_directory(value)
    from .native_read import enabled, authority
    if enabled():
        from .directory_access import DirectoryAccessService
        with authority(request, str(uuid4())) as current:
            return DirectoryAccessService(current).resolve(value)
    return None
