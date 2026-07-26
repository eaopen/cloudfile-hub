# -*- coding: utf-8 -*-
"""Read-only browse and download for external sources.

This is the data plane the capability exists for, and the reason it cannot
reuse Seahub's: a native download issues
``seafile_api.get_fileserver_access_token(repo_id, obj_id, ...)`` and hands the
browser a Go fileserver URL, but an external file has no content-addressed
obj_id and no blocks. The chain breaks at its first argument, so file bytes are
served from here instead. docs/external-sources.md section two states the
consequences -- sync, WebDAV and zip download are structurally unavailable, not
merely unimplemented.

Presentation is deliberately absent: these endpoints are consumed by the
CloudFile UI now (phase 2) and by the shadow layer later (phase 3), so nothing
here may assume either.
"""

import logging
import os
import posixpath

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django.http import FileResponse

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext.features import is_enabled
from cloudfile_ext.external_sources import paths, service
from cloudfile_ext.external_sources.models import ExternalSource
from cloudfile_ext.external_sources.providers import SourceError, SourceNotFound

logger = logging.getLogger(__name__)

#: Streamed in chunks rather than read whole: a source is a network mount and
#: the files on it can be arbitrarily large. 64 KiB is what Django's
#: FileResponse uses by default for the same reason.
CHUNK_SIZE = 64 * 1024


def _feature_off():
    return api_error(status.HTTP_404_NOT_FOUND,
                     'External sources are not enabled.')


def _denied():
    """One response for "no such source" and "not allowed to see it".

    Distinguishing them tells a caller which source ids exist, which is the
    same reason the ACL capability turned WebDAV's 403-on-invisible into a 409
    (FEATURES.md item 30) -- a status code difference alone was enough to
    confirm a hidden directory existed.
    """
    return api_error(status.HTTP_404_NOT_FOUND, 'Source not found.')


def _authorize(request, source_id, path='/'):
    """Return ``(source, error_response)`` -- exactly one of them is None."""
    source = ExternalSource.objects.filter(id=source_id, enabled=1).first()
    if source is None:
        return None, _denied()

    username = request.user.username
    permission = service.permission_for(
        username, source, path=path,
        is_staff=bool(getattr(request.user, 'is_staff', False)))
    if permission is None:
        return None, _denied()
    return source, None


class ExternalSourcesView(APIView):
    """Sources this user may read."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        username = request.user.username
        is_staff = bool(getattr(request.user, 'is_staff', False))

        visible = []
        for source in ExternalSource.objects.enabled_sources():
            permission = service.permission_for(username, source,
                                                is_staff=is_staff)
            if permission is None:
                continue
            visible.append(service.serialize_source(source, permission))

        return Response({'sources': visible})


class ExternalSourceDirView(APIView):
    """List a directory inside a source."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        try:
            path = paths.normalize_rel_path(request.GET.get('p', '/'))
        except paths.UnsafePath as exc:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p invalid: %s' % exc)

        source, error = _authorize(request, source_id, path)
        if error:
            return error

        try:
            entries = service.list_dir(source, path)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'Path not found.')
        except paths.UnsafePath:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p invalid.')
        except SourceError as exc:
            # 503, not 500: the source is unreachable, which is a transient
            # infrastructure state the caller may retry. Returning an empty
            # listing instead would render as "this share is empty now".
            logger.warning('listing external source %s failed: %s',
                           source.name, exc)
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')

        return Response({
            'source_id': source.id,
            'repo_id': source.repo_id,
            'path': path,
            'dirent_list': [service.serialize_entry(e, path) for e in entries],
        })


class ExternalSourceFileView(APIView):
    """Metadata for one file, or its contents.

    ``?op=download`` streams the bytes. One endpoint rather than two because
    both answers need the identical authorisation and containment work, and the
    download half is the one place where getting either wrong reads out
    arbitrary container files.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _feature_off()

        try:
            path = paths.normalize_rel_path(request.GET.get('p', ''))
        except paths.UnsafePath as exc:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p invalid: %s' % exc)
        if path == '/':
            return api_error(status.HTTP_400_BAD_REQUEST, 'p is required.')

        source, error = _authorize(request, source_id, path)
        if error:
            return error

        backend = None
        try:
            backend = service.backend_for(source)
            entry = backend.stat(source.root_path, path)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
        except paths.UnsafePath:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p invalid.')
        except SourceError as exc:
            logger.warning('reading external source %s failed: %s',
                           source.name, exc)
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')

        if entry.is_dir:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'p is a directory; use the dir endpoint.')

        if request.GET.get('op') != 'download':
            return Response(service.serialize_entry(
                entry, posixpath.dirname(path) or '/'))

        return self._download(source, backend, path, entry)

    def _download(self, source, backend, path, entry):
        try:
            handle_cm = backend.open_file(source.root_path, path)
            handle = handle_cm.__enter__()
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
        except paths.UnsafePath:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p invalid.')
        except SourceError as exc:
            logger.warning('opening external source %s failed: %s',
                           source.name, exc)
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')

        def close():
            try:
                handle_cm.__exit__(None, None, None)
            except Exception:
                logger.exception('closing external source file failed')

        # FileResponse closes the file object it is given once the response is
        # fully written, but the *context manager* also has to be exited, and
        # only it knows how a future backend (an SMB session, say) releases its
        # resources. Hence the explicit callback rather than relying on
        # FileResponse alone.
        response = FileResponse(
            handle, as_attachment=True,
            filename=os.path.basename(path),
            content_type='application/octet-stream')
        response._resource_closers.append(close)
        # No Content-Length from entry.size on purpose: the file may have been
        # replaced between stat and open, and a wrong length truncates or hangs
        # the transfer. FileResponse sets it from the handle it actually has.
        return response
