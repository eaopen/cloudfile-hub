# -*- coding: utf-8 -*-
"""Storage-class assignment API views (P2 storage backends).

Backend + API only; no UI. Views are enabled for an existing
Seafile V2 automatic local root or an explicitly enabled storage-class
deployment. This API never changes ordinary Seafile native repository routes.

- ``GET  /api/v2.1/cloudfile/storage-classes/`` lists the configured classes.
- ``POST /api/v2.1/cloudfile/repos/`` creates a repo pinned to ``storage_id``
  (the pin is written by seaf-server before the initial commit, so the repo is
  immediately routed to the chosen backend).
"""

import json

from cloudfile_ext.storage.key_policy import valid_repo_key
from pysearpc import SearpcError

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.utils import is_valid_dirent_name
from seaserv import seafile_api


def _storage_classes():
    """Return the configured classes as a list of dicts, or None on error."""
    raw = seafile_api.get_storage_classes()
    if raw is None:
        return None
    try:
        classes = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(classes, list):
        return None
    return classes


class StorageClassesView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        classes = _storage_classes()
        if classes is None:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Failed to load storage classes.')
        return Response({'storage_classes': classes})


class RepoWithStorageView(APIView):

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def post(self, request):
        username = request.user.username
        repo_name = request.data.get('name', '')
        if not repo_name:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'Library name is required.')
        if not is_valid_dirent_name(repo_name):
            return api_error(status.HTTP_400_BAD_REQUEST, 'name invalid.')

        storage_id = request.data.get('storage_id')
        repo_key = request.data.get('repo_key')
        classes = _storage_classes()
        if classes is None:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Failed to load storage classes.')
        automatic = any(c.get('is_auto') is True for c in classes)
        valid_ids = {c.get('storage_id') for c in classes if not c.get('is_auto')}
        if storage_id and storage_id not in valid_ids:
            return api_error(status.HTTP_400_BAD_REQUEST, 'storage_id invalid.')
        if repo_key is not None:
            # An explicit key chooses a physical directory. Only administrators
            # may specify it; ordinary users keep the native UUID default.
            if not request.user.is_staff:
                return api_error(status.HTTP_403_FORBIDDEN,
                                 'Explicit repo_key requires administrator privileges.')
            if (not valid_repo_key(repo_key) or storage_id or not automatic or
                    repo_key in valid_ids):
                return api_error(status.HTTP_400_BAD_REQUEST,
                                 'repo_key invalid or incompatible with storage class.')
            # No TOCTOU precheck or old cf_library_storage_key table. Native
            # RepoStorageId + cf_library_storage transaction is authoritative.

        payload = {
            'name': repo_name,
            'owner': username,
            # Retain the import intent marker so a lost create response can
            # be reconciled without creating a second library.
            'desc': request.data.get('desc', ''),
            'storage_id': storage_id or '',
        }
        if repo_key is not None:
            payload['repo_key'] = repo_key
        try:
            repo_id = seafile_api.create_repo_with_storage(json.dumps(payload))
        except SearpcError:
            # Native allocation can fail after reserving a key, writing the
            # first Commit, or recording its owner. A retry may create a second
            # library and an RPC error alone does not prove a UNIQUE conflict.
            # Never present a 409 or encourage an automatic retry without
            # inspecting the original repo/key status.
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Library allocation result is unknown; inspect storage before retrying.')
        if not repo_id:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Failed to create library.')

        result = {'repo_id': repo_id}
        if automatic and not storage_id:
            result['repo_key'] = repo_key or repo_id
            result['storage_id'] = 'auto-local:' + result['repo_key']
        return Response(result, status=status.HTTP_201_CREATED)
