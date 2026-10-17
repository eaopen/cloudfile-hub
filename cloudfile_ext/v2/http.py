"""Existing EAP identity lookup backed only by native CE14 Profile/User facts."""
from rest_framework import status
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from seahub.api2.authentication import TokenAuthentication, SessionAuthentication
from seahub.api2.base import APIView
from seahub.api2.utils import api_error
from seahub.base.accounts import User
from seahub.profile.models import Profile


class IdentityResolve(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        # Read-only UID lookup uses native staff authentication; it does not manage users.
        uid = request.data.get('external_user_id')
        if (not isinstance(uid, str) or not uid or uid != uid.strip() or len(uid) > 225
                or request.data.get('login_id') != uid):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Stable UID required.')
        username = Profile.objects.get_username_by_login_id(uid)
        if username is None:
            return api_error(status.HTTP_404_NOT_FOUND, 'User must sign in through SSO first.')
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return api_error(status.HTTP_404_NOT_FOUND, 'Native user not found.')
        return Response({'external_user_id': uid, 'login_id': uid,
                         'email': user.username, 'is_active': bool(user.is_active)})


class GroupResolve(APIView):
    """Resolve an existing Etech entity to its native Group, without provisioning."""
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        from django.db import connection
        from seahub.utils.db_api import SeafileDB
        external = request.data.get('external_group_id')
        if (not isinstance(external, str) or not external or external != external.strip()
                or external == 'role:' or len(external) > 225):
            return api_error(status.HTTP_400_BAD_REQUEST, 'External group ID required.')
        role = external.startswith('role:')
        external = external[5:] if role else external
        kinds = ('group', 'role') if role else ('dept', 'org')
        schema = connection.ops.quote_name(SeafileDB().db_name)
        with connection.cursor() as cursor:
            cursor.execute('SELECT DISTINCT group_id FROM ' + schema + '.cf_sso_group_map '
                           'WHERE provider=%s AND subject_type IN (%s,%s) AND external_id=%s',
                           ('etech', *kinds, external))
            groups = cursor.fetchall()
        if not groups:
            return api_error(status.HTTP_404_NOT_FOUND, 'External group is not mapped.')
        if len(groups) != 1:
            return api_error(status.HTTP_409_CONFLICT, 'External group mapping is ambiguous.')
        return Response({'group_id': groups[0][0]})


class NativeLibraries(APIView):
    """Read-only inventory of pre-V2 native repositories, for Etech review.

    Only rows explicitly reconciled as native are returned. Newly-created
    CloudFile V2 routed repositories are never candidates for Etech adoption.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def get(self, request):
        from django.db import connection
        from seahub.utils.db_api import SeafileDB
        from seaserv import seafile_api
        if not request.user.admin_permissions.can_manage_library():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
        try:
            page = int(request.GET.get('page', '1'))
            limit = int(request.GET.get('per_page', '100'))
        except (TypeError, ValueError):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid pagination.')
        if not (1 <= page <= 200 and 1 <= limit <= 100):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid pagination.')
        schema = connection.ops.quote_name(SeafileDB().db_name)
        # Strict key prefix, state and native Repo binding. No record is
        # created or repaired by an HTTP read; the installer reconciles first.
        with connection.cursor() as cursor:
            cursor.execute('SELECT c.repo_id FROM ' + schema + '.cf_library_storage c '
                           'INNER JOIN ' + schema + '.Repo r ON r.repo_id=c.repo_id '
                           'LEFT JOIN ' + schema + '.RepoStorageId s ON s.repo_id=c.repo_id '
                           "WHERE c.repo_key=CONCAT('native-',c.repo_id) AND c.state='active' "
                           'AND s.repo_id IS NULL '
                           'ORDER BY c.repo_id LIMIT %s OFFSET %s',
                           (limit + 1, (page - 1) * limit))
            ids = [row[0] for row in cursor.fetchall()]
        result = []
        for repo_id in ids[:limit]:
            repo = seafile_api.get_repo(repo_id)
            if repo is None or not repo.name:
                # Present but unreadable native repo needs separate recovery;
                # do not create an Etech business row for a broken resource.
                continue
            result.append({'id': repo_id, 'name': repo.name})
        return Response({'repos': result, 'page_info': {
            'current_page': page, 'has_next_page': len(ids) > limit}})
