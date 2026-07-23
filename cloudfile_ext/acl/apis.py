# -*- coding: utf-8 -*-
"""Directory ACL management endpoints.

Managing ACL on a folder is itself a privileged operation: only someone with
read-write access to the folder *and* ownership of the library may change it.
Requiring plain `rw` would let anyone a folder was shared with re-share it
more widely.
"""

import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from seaserv import seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.constants import PERMISSION_READ_WRITE

from cloudfile_ext.features import is_enabled
from cloudfile_ext.acl import resolver, service
from cloudfile_ext.acl.models import DirACL

logger = logging.getLogger(__name__)

VALID_PERMISSIONS = tuple(resolver.PERMISSION_ORDER)
VALID_SUBJECT_TYPES = (resolver.SUBJECT_USER, resolver.SUBJECT_DEPT,
                       resolver.SUBJECT_GROUP)


def _feature_off():
    return api_error(status.HTTP_404_NOT_FOUND, 'Directory ACL is not enabled.')


def _check_can_manage(request, repo_id, path):
    """Return an error Response, or None when the caller may manage ACL here.

    Ownership is required so that a user a folder was merely shared with
    cannot re-share it more widely.

    The permission check deliberately uses the *native* repo permission rather
    than check_folder_permission: the latter now applies the directory ACL, so
    an owner who wrote a restrictive rule covering themselves would be locked
    out of the very endpoint needed to remove it.
    """
    repo = seafile_api.get_repo(repo_id)
    if not repo:
        return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')

    if not seafile_api.get_dir_id_by_path(repo_id, path):
        return api_error(status.HTTP_404_NOT_FOUND, 'Folder not found.')

    username = request.user.username
    if seafile_api.check_permission(repo_id, username) != PERMISSION_READ_WRITE:
        return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')

    if seafile_api.get_repo_owner(repo_id) != username:
        return api_error(status.HTTP_403_FORBIDDEN,
                         'Only the library owner can manage directory ACL.')
    return None


def _serialize(rule):
    return {
        'repo_id': rule.repo_id,
        'path': rule.path,
        'subject_type': rule.subject_type,
        'subject': rule.subject,
        'permission': rule.permission,
        'inherit': bool(rule.inherit),
        'mtime': rule.mtime,
    }


class DirACLView(APIView):
    """List, set and delete ACL rules on one folder."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        rules = DirACL.objects.filter(
            repo_id=repo_id, path_hash=resolver.path_hash(path))
        return Response({'path': path,
                         'rules': [_serialize(r) for r in rules]})

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.data.get('path', '/'))
        subject_type = request.data.get('subject_type', '')
        subject = request.data.get('subject', '')
        permission = request.data.get('permission', '')
        inherit = request.data.get('inherit', True)

        if subject_type not in VALID_SUBJECT_TYPES:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject_type invalid.')
        if not subject:
            return api_error(status.HTTP_400_BAD_REQUEST, 'subject invalid.')
        if permission not in VALID_PERMISSIONS:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'permission invalid.')

        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        try:
            rule = DirACL.objects.set_rule(
                repo_id, path, subject_type, subject, permission,
                inherit=bool(inherit))
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        service.invalidate_repo(repo_id)
        return Response(_serialize(rule))

    def delete(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        subject_type = request.GET.get('subject_type', '')
        subject = request.GET.get('subject', '')

        if subject_type not in VALID_SUBJECT_TYPES or not subject:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject_type or subject invalid.')

        error = _check_can_manage(request, repo_id, path)
        if error:
            return error

        try:
            DirACL.objects.delete_rule(repo_id, path, subject_type, subject)
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        service.invalidate_repo(repo_id)
        return Response({'success': True})


class DirACLEffectiveView(APIView):
    """Show the effective permission a user has on a path, and why.

    Exists because inheritance across levels and subject types is hard to
    reason about from the raw rule list; support needs to be able to answer
    "why can B not open this folder" without reading the table by hand.
    """

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        path = resolver.normalize_path(request.GET.get('path', '/'))
        # Checking another user's effective permission is an admin-grade
        # disclosure, so it is gated the same way rule management is.
        target = request.GET.get('user', '') or request.user.username
        if target != request.user.username:
            error = _check_can_manage(request, repo_id, path)
            if error:
                return error

        native = seafile_api.check_permission(repo_id, target)
        effective = service.apply_dir_acl(target, repo_id, path, native)

        return Response({
            'path': path,
            'user': target,
            'native_permission': native,
            'effective_permission': effective,
            'levels': resolver.ancestors(path),
        })
