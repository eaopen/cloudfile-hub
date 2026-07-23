# -*- coding: utf-8 -*-
"""System-admin endpoints for directory ACL.

Separate from apis.py because these bypass library ownership: an
administrator has to be able to inspect and repair ACL on libraries they do
not own, including ones whose owner has left.
"""

import logging

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seaserv import seafile_api

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext.features import is_enabled
from cloudfile_ext.acl import resolver, service, subjects
from cloudfile_ext.acl.apis import (
    VALID_PERMISSIONS, VALID_SUBJECT_TYPES, _serialize, _feature_off,
)

logger = logging.getLogger(__name__)

#: A repo can accumulate a lot of rules; cap one response so an admin listing
#: cannot turn into an accidental full-table scan.
MAX_RULES_PER_PAGE = 500


class AdminDirACLView(APIView):
    """List every rule in a library, or replace a rule, as an administrator."""

    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl.models import DirACL

        try:
            page = int(request.GET.get('page', '1'))
            per_page = min(int(request.GET.get('per_page', '100')),
                           MAX_RULES_PER_PAGE)
        except ValueError:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'page or per_page invalid.')
        if page < 1 or per_page < 1:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'page or per_page invalid.')

        qs = DirACL.objects.filter(repo_id=repo_id).order_by('path', 'id')
        total = qs.count()
        start = (page - 1) * per_page
        rules = qs[start:start + per_page]

        return Response({
            'repo_id': repo_id,
            'total': total,
            'page': page,
            'per_page': per_page,
            'rules': [_serialize(r) for r in rules],
        })

    def post(self, request, repo_id):
        if not is_enabled('CF_ENABLE_DIR_ACL'):
            return _feature_off()

        from cloudfile_ext.acl.models import DirACL

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

        if not seafile_api.get_repo(repo_id):
            return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')

        # As in the owner-facing endpoint: store the identity enforcement
        # compares, not what was typed. See cloudfile_ext/acl/subjects.py.
        try:
            subject = subjects.resolve(subject_type, subject)
        except subjects.UnknownSubject as e:
            return api_error(status.HTTP_400_BAD_REQUEST,
                             'subject not found: %s' % e)

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

        from cloudfile_ext.acl.models import DirACL

        path = request.GET.get('path')
        subject_type = request.GET.get('subject_type', '')
        subject = request.GET.get('subject', '')

        try:
            if path is None:
                # Clearing a whole library's ACL is the "owner has left and
                # nobody can get in" escape hatch.
                DirACL.objects.filter(repo_id=repo_id).delete()
            else:
                if subject_type not in VALID_SUBJECT_TYPES or not subject:
                    return api_error(status.HTTP_400_BAD_REQUEST,
                                     'subject_type or subject invalid.')
                try:
                    subject = subjects.resolve(subject_type, subject)
                except subjects.UnknownSubject as e:
                    return api_error(status.HTTP_400_BAD_REQUEST,
                                     'subject not found: %s' % e)
                DirACL.objects.delete_rule(
                    repo_id, resolver.normalize_path(path), subject_type,
                    subject)
        except Exception as e:
            logger.error(e)
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR,
                             'Internal Server Error')

        service.invalidate_repo(repo_id)
        return Response({'success': True})
