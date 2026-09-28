# -*- coding: utf-8 -*-
"""Authenticated cleanup for abandoned browser resumable uploads."""

import logging
import posixpath

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seaserv import seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.utils import normalize_file_path
from seahub.utils.repo import parse_repo_perm
from seahub.views import check_folder_permission

logger = logging.getLogger(__name__)


class UploadTempFileView(APIView):
    """Discard one stale temporary upload after explicit user confirmation."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def delete(self, request, repo_id):
        parent_dir = request.query_params.get('parent_dir', '')
        file_name = request.query_params.get('file_name', '')
        if not parent_dir or not file_name or posixpath.basename(file_name) != file_name:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Upload path invalid.')
        if not seafile_api.get_repo(repo_id):
            return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')

        parent_dir = normalize_file_path(parent_dir)
        if not seafile_api.get_dir_id_by_path(repo_id, parent_dir):
            return api_error(status.HTTP_404_NOT_FOUND, 'Folder not found.')
        permission = check_folder_permission(request, repo_id, parent_dir)
        if not permission or parse_repo_perm(permission).can_edit_on_web is False:
            return api_error(status.HTTP_403_FORBIDDEN, 'Write permission required.')

        file_path = posixpath.join(parent_dir, file_name)
        try:
            seafile_api.cf_discard_upload_tmp_file(repo_id, file_path)
        except Exception:
            # CloudFile: fail closed. Returning success while cleanup failed
            # would make the browser upload from zero into an untruncated file.
            logger.exception('Failed to discard upload temp file %s:%s',
                             repo_id, file_path)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Failed to discard temporary upload.')
        return Response({'success': True})
