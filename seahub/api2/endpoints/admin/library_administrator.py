"""Remove a library management marker without revoking any content share."""
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
from seahub.share.models import ExtraSharePermission, ExtraGroupsSharePermission
from seahub.utils import is_valid_email, send_perm_audit_msg

logger = logging.getLogger(__name__)


class AdminLibraryAdministrator(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def delete(self, request, repo_id):
        if not request.user.admin_permissions.can_manage_library():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
        if set(request.GET) != {'subject_type', 'subject'} or any(len(request.GET.getlist(k)) != 1 for k in request.GET):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid administrator target.')
        kind, subject = request.GET['subject_type'], request.GET['subject']
        if kind == 'user':
            if not is_valid_email(subject):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid user.')
            store = ExtraSharePermission
        elif kind == 'group' and subject.isascii() and subject.isdecimal() and 0 < int(subject) <= 2147483647:
            subject = int(subject)
            store = ExtraGroupsSharePermission
        else:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid subject.')
        try:
            if not seafile_api.get_repo(repo_id):
                return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
            # Never call remove_share/unset_group_repo or write a content permission.
            # Deleting only Extra* preserves direct and inherited r/rw qualification.
            store.objects.delete_share_permission(repo_id, subject)
            send_perm_audit_msg('modify-repo-perm', request.user.username, subject,
                                repo_id, '/', 'revoke-admin')
            result = Response({'repo_id': repo_id, 'subject_type': kind, 'subject': str(subject), 'removed': True})
            result['Cache-Control'] = 'no-store'
            return result
        except Exception:
            logger.exception('Library administrator removal failed')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Administrator service unavailable.')
