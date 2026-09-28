"""CloudFile library technical settings; business metadata belongs to adapters."""
import logging

from seaserv import seafile_api
from rest_framework import status
from rest_framework.response import Response

from seahub.admin_log.models import REPO_CONFIG
from seahub.admin_log.signals import admin_operation
from seahub.api2.endpoints.admin.library_administrator import AdminLibraryAdministrator
from seahub.api2.utils import api_error
from seahub.utils import is_valid_dirent_name
from seahub.utils.repo import normalize_repo_status_str

logger = logging.getLogger(__name__)


class LibraryConfiguration(AdminLibraryAdministrator):
    """A single-field update avoids partial success across native RPC operations."""
    http_method_names = ('get', 'put')

    def _document(self, request, repo_id):
        repo = seafile_api.get_repo(repo_id)
        if not repo:
            return api_error(status.HTTP_404_NOT_FOUND, 'Library not found.')
        history = seafile_api.get_repo_history_limit(repo_id)
        if type(history) is not int:
            raise ValueError('Invalid native history limit')
        native_status = repo.status
        if type(native_status) is not int or native_status not in (0, 1):
            raise ValueError('Invalid native library status')
        response = Response({
            'repo_id': repo_id,
            'name': repo.repo_name,
            'owner': seafile_api.get_repo_owner(repo_id) or seafile_api.get_org_repo_owner(repo_id),
            'encrypted': bool(repo.encrypted),
            'status': native_status,
            'history_keep_days': history,
            'can_manage': True,
            'can_set_status': bool(request.user.is_staff and request.user.admin_permissions.can_manage_library()),
        })
        response['Cache-Control'] = 'no-store'
        return response

    def get(self, request, repo_id):
        if request.GET:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Query parameters are not supported.')
        try:
            denied = self._authorize(request, repo_id)
            return denied if denied is not None else self._document(request, repo_id)
        except Exception:
            logger.exception('Library configuration lookup failed')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Library configuration unavailable.')

    def put(self, request, repo_id):
        if request.GET or len(request.data) != 1:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Exactly one setting is required.')
        key, value = next(iter(request.data.items()))
        if key == 'name':
            if not isinstance(value, str) or not is_valid_dirent_name(value):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid library name.')
        elif key == 'history_keep_days':
            if type(value) is not int or value < -1 or value > 36500:
                return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid history retention.')
        elif key == 'status':
            if value not in ('normal', 'read-only'):
                return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid library status.')
            if not (request.user.is_staff and request.user.admin_permissions.can_manage_library()):
                return api_error(status.HTTP_403_FORBIDDEN, 'System library management is required.')
        else:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Unsupported library setting.')
        try:
            denied = self._authorize(request, repo_id)
            if denied is not None:
                return denied
            if key == 'name':
                if seafile_api.edit_repo(repo_id, value, '', None) == -1:
                    raise ValueError('Native rename failed')
            elif key == 'history_keep_days':
                if seafile_api.set_repo_history_limit(repo_id, value) != 0:
                    raise ValueError('Native history update failed')
            else:
                seafile_api.set_repo_status(repo_id, normalize_repo_status_str(value))
            result = self._document(request, repo_id)
            expected = (0 if value == 'normal' else 1) if key == 'status' else value
            if result.data[{'history_keep_days': 'history_keep_days', 'status': 'status', 'name': 'name'}[key]] != expected:
                raise ValueError('Native setting read-back mismatch')
            admin_operation.send(sender=None, admin_name=request.user.username,
                                 operation=REPO_CONFIG, detail={'id': repo_id, 'setting': key, 'value': value})
            return result
        except Exception:
            logger.exception('Library configuration update failed')
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Library configuration update unconfirmed.')
