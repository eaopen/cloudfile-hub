# -*- coding: utf-8 -*-
"""Search the external documents written by the bounded scanner."""

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
from cloudfile_ext.external_sources import service
from cloudfile_ext.external_sources.models import ExternalSource


class ExternalSourceSearchView(APIView):
    """Search only sources already visible to the requesting user.

    Synthetic repositories stay out of Seahub's native search permission map,
    so this endpoint avoids changing the upstream search protocol.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        if not is_enabled('CF_ENABLE_EXTERNAL_SOURCES'):
            return api_error(status.HTTP_404_NOT_FOUND,
                             'External sources are not enabled.')
        from django.conf import settings
        if getattr(settings, 'CF_PROVIDER_SEARCH', '') != 'meilisearch':
            return api_error(status.HTTP_404_NOT_FOUND,
                             'External source search requires Meilisearch.')

        query = request.GET.get('q', '').strip()
        if not query:
            return api_error(status.HTTP_400_BAD_REQUEST, 'q is required.')
        try:
            offset = max(0, int(request.GET.get('offset', 0)))
            limit = min(100, max(1, int(request.GET.get('limit', 50))))
        except ValueError:
            return api_error(status.HTTP_400_BAD_REQUEST, 'offset or limit is invalid.')

        is_staff = bool(getattr(request.user, 'is_staff', False))
        visible = []
        source_by_repo = {}
        for source in ExternalSource.objects.enabled_sources():
            if service.permission_for(request.user.username, source,
                                      is_staff=is_staff) is not None:
                visible.append(source.repo_id)
                source_by_repo[source.repo_id] = source
        if not visible:
            return Response({'results': [], 'total': 0})

        from cloudfile_ext.search.backends.meilisearch import (
            MeilisearchError, client_from_settings,
        )
        try:
            response = client_from_settings().search(
                query, 'repo_id IN %s' % json.dumps(visible, ensure_ascii=False),
                offset, limit, filename_only=True)
        except MeilisearchError:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Search is currently unavailable.')

        results = []
        for hit in response.get('hits', []):
            source = source_by_repo.get(hit.get('repo_id'))
            if source is None:
                continue
            results.append({
                'source_id': source.id,
                'repo_id': source.repo_id,
                'source_name': source.name,
                'path': hit.get('path', ''),
                'name': hit.get('name', ''),
                'size': hit.get('size', 0),
                'mtime': hit.get('mtime', 0),
            })
        return Response({'results': results,
                         'total': response.get('estimatedTotalHits', len(results))})
