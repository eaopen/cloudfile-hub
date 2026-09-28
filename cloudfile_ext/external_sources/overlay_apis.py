# -*- coding: utf-8 -*-
"""Metadata/tag sidecar for external paths, never a Seafile file mutation."""

import json

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext.features import is_enabled
from cloudfile_ext.external_sources import paths, service
from cloudfile_ext.external_sources.models import ExternalOverlay, ExternalSource
from cloudfile_ext.external_sources.providers import SourceError, SourceNotFound


def _off():
    return api_error(status.HTTP_404_NOT_FOUND, 'External sources are not enabled.')


def _source_for(request, source_id, path):
    source = ExternalSource.objects.filter(id=source_id, enabled=1).first()
    if source is None:
        return None, api_error(status.HTTP_404_NOT_FOUND, 'Source not found.')
    permission = service.permission_for(
        request.user.username, source, path,
        is_staff=bool(getattr(request.user, 'is_staff', False)))
    if permission is None:
        return None, api_error(status.HTTP_404_NOT_FOUND, 'Source not found.')
    return source, None


def _decode(value, fallback):
    try:
        return json.loads(value) if value else fallback
    except (TypeError, ValueError):
        return fallback


class ExternalOverlayView(APIView):
    """Read an overlay as a source reader; write it as a system administrator."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _off()
        try:
            path = paths.normalize_rel_path(request.GET.get('p', ''))
        except paths.UnsafePath as exc:
            return api_error(status.HTTP_400_BAD_REQUEST, 'p invalid: %s' % exc)
        if path == '/':
            return api_error(status.HTTP_400_BAD_REQUEST, 'p is required.')
        source, error = _source_for(request, source_id, path)
        if error:
            return error
        overlay = ExternalOverlay.objects.get_overlay(source.id, path)
        return Response({
            'source_id': source.id,
            'path': path,
            'metadata': _decode(overlay.metadata, {}) if overlay else {},
            'tags': _decode(overlay.tags, []) if overlay else [],
            'mtime': overlay.mtime if overlay else None,
        })

    def put(self, request, source_id):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return _off()
        if not bool(getattr(request.user, 'is_staff', False)):
            return api_error(status.HTTP_403_FORBIDDEN,
                             'Only system administrators may edit external overlays.')
        try:
            path = paths.normalize_rel_path(request.data.get('path', ''))
        except paths.UnsafePath as exc:
            return api_error(status.HTTP_400_BAD_REQUEST, 'path invalid: %s' % exc)
        if path == '/':
            return api_error(status.HTTP_400_BAD_REQUEST, 'path is required.')
        source, error = _source_for(request, source_id, path)
        if error:
            return error
        try:
            # Do not leave metadata for a misspelled or already deleted
            # mounted path. The sidecar is anchored to a live external entry.
            service.backend_for(source).stat(source.root_path, path)
        except SourceNotFound:
            return api_error(status.HTTP_404_NOT_FOUND, 'External path not found.')
        except (SourceError, paths.UnsafePath):
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Source is currently unreachable.')
        metadata = request.data.get('metadata')
        tags = request.data.get('tags')
        if metadata is not None and not isinstance(metadata, dict):
            return api_error(status.HTTP_400_BAD_REQUEST, 'metadata must be an object.')
        if tags is not None and (not isinstance(tags, list) or
                                 any(not isinstance(tag, str) or not tag.strip()
                                     for tag in tags)):
            return api_error(status.HTTP_400_BAD_REQUEST, 'tags must be strings.')
        if metadata is None and tags is None:
            return api_error(status.HTTP_400_BAD_REQUEST, 'metadata or tags is required.')
        if tags is not None:
            tags = sorted(set(tag.strip() for tag in tags))
        overlay = ExternalOverlay.objects.update_overlay(source.id, path, metadata, tags)
        return Response({
            'source_id': source.id, 'path': path,
            'metadata': _decode(overlay.metadata, {}),
            'tags': _decode(overlay.tags, []), 'mtime': overlay.mtime,
        })
