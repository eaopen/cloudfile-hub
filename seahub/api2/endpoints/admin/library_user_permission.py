"""Administrative library qualification lookup, separate from path content ACL."""
import logging

from seaserv import seafile_api
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error
from seahub.base.accounts import User
from seahub.auth.utils import get_virtual_id_by_email
from seahub.share.utils import is_repo_admin
from seahub.utils import is_valid_email

logger = logging.getLogger(__name__)


class AdminLibraryUserPermission(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request, repo_id):
        # Querying another user's grants is a management operation, not a content read.
        if not request.user.admin_permissions.can_manage_library():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
        if set(request.GET) != {'email'} or len(request.GET.getlist('email')) != 1:
            return api_error(status.HTTP_400_BAD_REQUEST, 'A single email is required.')
        email = request.GET['email'].strip()
        if not is_valid_email(email):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Email invalid.')
        try:
            if not seafile_api.get_repo(repo_id):
                return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
            try:
                user = User.objects.get(email=get_virtual_id_by_email(email))
            except User.DoesNotExist:
                return api_error(status.HTTP_404_NOT_FOUND, 'User not found.')
            org_owner_lookup = getattr(seafile_api, 'get_org_repo_owner', None)
            owner = seafile_api.get_repo_owner(repo_id) or (
                org_owner_lookup(repo_id) if org_owner_lookup else None)
            if not owner:
                raise ValueError('Library owner unavailable')
            # Use native library qualification; do not impersonate the user or scan directories.
            permission = seafile_api.check_permission(repo_id, user.username) if user.is_active else None
            if permission not in (None, '', 'r', 'rw'):
                raise ValueError('Unsupported native library permission')
            repo_admin = bool(is_repo_admin(user.username, repo_id, strict=True)) if user.is_active else False
            response = Response(dict(repo_id=repo_id, email=email, permission=permission or 'none',
                repo_admin=repo_admin, is_owner=owner == user.username, is_active=bool(user.is_active),
                permission_scope='library', directory_acl_applied=False))
            response['Cache-Control'] = 'no-store'
            return response
        except Exception:
            # A failed permission lookup must not masquerade as a successful "none" result.
            logger.exception('Administrative library permission lookup failed')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Permission service unavailable.')
