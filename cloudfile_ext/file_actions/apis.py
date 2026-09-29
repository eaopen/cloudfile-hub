# -*- coding: utf-8 -*-
"""Authenticated file-action and local-Agent endpoints."""

import os
import tempfile

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seaserv import seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.utils import normalize_file_path
from seahub.utils.repo import parse_repo_perm
from seahub.views import check_folder_permission

from cloudfile_ext.features import is_enabled
from cloudfile_ext.file_actions import service


def _feature_off():
    return api_error(status.HTTP_404_NOT_FOUND, 'File actions are not enabled.')


def _get_file(request, repo_id, path, require_edit=False):
    if not path:
        return None, api_error(status.HTTP_400_BAD_REQUEST, 'path invalid.')
    path = normalize_file_path(path)
    if not seafile_api.get_repo(repo_id):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
    if not seafile_api.get_file_id_by_path(repo_id, path):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
    permission = check_folder_permission(request, repo_id, path)
    if not permission:
        return None, api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
    if require_edit and parse_repo_perm(permission).can_edit_on_web is False:
        return None, api_error(status.HTTP_403_FORBIDDEN, 'Edit permission required.')
    return path, None


def _get_file_for_admin(repo_id, path):
    """Locate a file without applying its owner's library permission rules."""
    if not path:
        return None, api_error(status.HTTP_400_BAD_REQUEST, 'path invalid.')
    path = normalize_file_path(path)
    if not seafile_api.get_repo(repo_id):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
    if not seafile_api.get_file_id_by_path(repo_id, path):
        return None, api_error(status.HTTP_404_NOT_FOUND, 'File not found.')
    return path, None


class _FileActionAPIView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)


class FileActionsView(_FileActionAPIView):
    """List relevant actions after a real, path-level permission check."""

    def get(self, request, repo_id):
        enabled = any(is_enabled(name) for name in (
            'CF_ENABLE_FILE_PREVIEW', 'CF_ENABLE_CHECKOUT', 'CF_ENABLE_LOCAL_APP',
        ))
        if not enabled:
            return _feature_off()
        path, error = _get_file(request, repo_id, request.GET.get('path', ''))
        if error:
            return error
        permission = check_folder_permission(request, repo_id, path)
        return Response({'repo_id': repo_id, 'path': path,
                         'actions': service.get_actions(
                             repo_id, path,
                             can_edit=parse_repo_perm(permission).can_edit_on_web)})


class LocalSessionView(_FileActionAPIView):
    """Issue a read-only hand-off for a Native Messaging Agent.

    Local write sessions are intentionally refused until the lock provider is
    registered in seafile-server.  That protects against a desktop client,
    WebDAV or an OnlyOffice callback bypassing a Hub-only checkout record.
    """

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_LOCAL_APP'):
            return _feature_off()
        mode = request.data.get('mode', 'local-view')
        path, error = _get_file(
            request, repo_id, request.data.get('path', ''),
            require_edit=mode in ('local-edit', 'local-edit-exclusive'))
        if error:
            return error
        if mode == 'local-view':
            return Response(service.issue_local_view_session(
                repo_id, path, request.user.username), status=status.HTTP_201_CREATED)
        if mode == 'local-edit':
            # 普通本地编辑：免锁，下载到本地镜像目录，手动上传。
            return Response(service.issue_local_edit_session(
                repo_id, path, request.user.username), status=status.HTTP_201_CREATED)
        if mode != 'local-edit-exclusive':
            return api_error(status.HTTP_400_BAD_REQUEST, 'mode invalid.')
        return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Exclusive editing is not enabled.')


class AgentSessionClaimView(APIView):
    """Exchange one browser-visible ticket for agent-only file capabilities."""

    authentication_classes = ()
    permission_classes = ()
    throttle_classes = (UserRateThrottle,)

    def post(self, request):
        if not is_enabled('CF_ENABLE_LOCAL_APP'):
            return _feature_off()
        ticket = request.data.get('ticket', '')
        if not isinstance(ticket, str) or not ticket:
            return api_error(status.HTTP_400_BAD_REQUEST, 'ticket invalid.')
        origin = request.build_absolute_uri('/').rstrip('/')
        claimed = service.claim_agent_session(ticket, origin)
        if not claimed:
            return api_error(status.HTTP_410_GONE, 'Local session is unavailable or expired.')
        return Response(claimed)
