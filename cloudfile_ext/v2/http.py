"""EAP identity preparation backed by trusted Directory and native CE facts."""
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
        # Native staff authentication authorizes lookup; Directory proves new UIDs.
        uid = request.data.get('external_user_id')
        if (not isinstance(uid, str) or not uid or uid != uid.strip() or len(uid) > 225
                or any(ord(c) < 32 or ord(c) == 127 for c in uid)
                or request.data.get('login_id') != uid):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Stable UID required.')
        # Check exact stored values after native collation matching; never
        # choose an arbitrary owner for a duplicate UID or case alias.
        rows = list(Profile.objects.filter(login_id=uid).values_list('user', 'login_id'))
        if rows and (len(rows) != 1 or rows[0][1] != uid):
            return api_error(status.HTTP_409_CONFLICT, 'Native UID binding conflict.')
        username = rows[0][0] if rows else None
        if username is None:
            # A staff request is not identity proof: independently read the
            # scoped enterprise Directory before creating any native account.
            from .directory_adapter import prepare_user
            from .errors import IdentityConflict, IdentityUnavailable
            try:
                username = prepare_user(uid)
            except IdentityConflict:
                return api_error(status.HTTP_409_CONFLICT, 'Native UID binding conflict.')
            except Exception:
                return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Trusted user preparation unavailable; sign in through SSO or restore Directory.')
        profile = Profile.objects.get_profile_by_user(username)
        if (profile is None or profile.login_id != uid
                or username.lower() in ('cfadmin@auth.local',)):
            return api_error(status.HTTP_409_CONFLICT, 'Native UID binding conflict.')
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return api_error(status.HTTP_404_NOT_FOUND, 'Native user not found.')
        if user.username != username or not user.is_active:
            return api_error(status.HTTP_409_CONFLICT, 'Native user inactive or changed.')
        return Response({'external_user_id': uid, 'login_id': uid,
                         'email': user.username, 'is_active': bool(user.is_active)})


class GroupResolve(APIView):
    """Prepare an exact trusted enterprise Directory entity as a native CE Group."""
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        external = request.data.get('external_group_id')
        if (not isinstance(external, str) or not external or external != external.strip()
                or external == 'role:' or len(external) > 225):
            return api_error(status.HTTP_400_BAD_REQUEST, 'External group ID required.')
        from .directory_adapter import prepare_group, lookup_group
        from .errors import IdentityConflict
        try:
            # Catalog verifies type/namespace/exact ID and native flat Group;
            # an old mapping or equal display name is never identity proof.
            existing = lookup_group(external)
            return Response({'group_id': existing if existing is not None else prepare_group(external)})
        except IdentityConflict:
            return api_error(status.HTTP_409_CONFLICT, 'Native group binding conflict.')
        except Exception:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Trusted group preparation unavailable.')


class CatalogSync(APIView):
    """enterprise Provider trigger; CloudFile reads only trusted entity catalog."""
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        if request.data:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Catalog trigger accepts no user-supplied snapshot.')
        if not request.user.admin_permissions.can_manage_group():
            return api_error(status.HTTP_403_FORBIDDEN, 'Native group management denied.')
        from .directory_adapter import sync_entity_catalog
        try:
            result = sync_entity_catalog()
        except Exception:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Trusted directory catalog reconciliation unavailable.')
        response = Response(result)
        response['Cache-Control'] = 'no-store'
        return response



class StorageReconcile(APIView):
    """Check only the bindings submitted by the administrator."""
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        from .native_discovery import inspect_from_hub
        if not request.user.admin_permissions.can_manage_library():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
        ids = request.data.get('repo_ids', [])
        if not isinstance(ids, list) or len(ids) > 5000 or any(not isinstance(x, str) for x in ids):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid repo_ids list.')
        if len(ids) != len(set(ids)):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Duplicate repo_ids.')
        try:
            states = inspect_from_hub(ids, with_features=True)
        except ValueError:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid Repo UUID.')
        except Exception:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Native library inventory unavailable.')
        response = Response({'registered': 0, 'statuses': states})
        response['Cache-Control'] = 'no-store'
        return response


class RepoFeatures(APIView):
    """Patch only explicitly managed capabilities and read back the committed intent."""
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request, repo_id):
        from django.db import connection, transaction
        from seahub.utils.db_api import SeafileDB
        from .schema import identifier
        if not request.user.admin_permissions.can_manage_library():
            return api_error(403, 'Permission denied.')
        changes = request.data
        if not isinstance(changes, dict) or not changes or any(
                key not in ('checkout', 'protection') or type(value) is not bool
                for key, value in changes.items()):
            return api_error(400, 'Expected boolean repository capability changes.')
        rid = str(repo_id)
        db = identifier(SeafileDB().db_name) + '.'
        table = db + 'cf_repo_feature'
        with transaction.atomic(), connection.cursor() as cursor:
            # Serialize with native publishing on the same master branch. A stale
            # binding must never create configuration for a missing or virtual repo.
            cursor.execute('SELECT b.commit_id FROM ' + db + 'Branch b JOIN ' + db +
                           'Repo r ON r.repo_id=b.repo_id WHERE b.repo_id=%s AND b.name=%s '
                           'AND NOT EXISTS (SELECT 1 FROM ' + db +
                           'VirtualRepo v WHERE v.repo_id=b.repo_id) FOR UPDATE', (rid, 'master'))
            if cursor.fetchone() is None:
                return api_error(404, 'Native repository unavailable.')
            cursor.execute('SELECT feature FROM ' + table +
                           ' WHERE repo_id=%s FOR UPDATE', (rid,))
            current = {row[0] for row in cursor.fetchall()}
            # 修改原因（2026-11-16）：关闭库级 protection 会让原生屏障立即消失，
            # 已定版原件随即可被覆盖、删除、改名；残留的 cf_file_protection 行还会让
            # 状态查询继续报 protected=true，重新开启后保护的是关闭期间被改写的内容，
            # 且该路径的 protect 会一直 409。因此有残留定版记录时必须拒绝关闭。
            # 校验放在任何写操作之前：同一请求若还带 checkout 变更，也不能出现
            # checkout 已落库、protection 被拒的部分应用。
            if changes.get('protection') is False and 'protection' in current:
                cursor.execute('SELECT 1 FROM ' + db +
                               'cf_file_protection WHERE repo_id=%s LIMIT 1', (rid,))
                if cursor.fetchone() is not None:
                    return api_error(409, 'Protected files must be unprotected before '
                                          'disabling protection for this library.')
            # Checkout is a time-bound reservation, not a detachable switch.
            # A live Guard cannot be abandoned by turning off its repository
            # policy: otherwise the holder's lease would be bypassed by normal
            # writes before expiry. Use the same Branch lock order as native
            # checkout/renew/release and refuse the whole multi-feature patch.
            if changes.get('checkout') is False:
                cursor.execute('SELECT 1 FROM ' + db +
                               'cf_edit_guard WHERE repo_id=%s AND guard_id IS NOT NULL '
                               'AND lease_expires_at>UTC_TIMESTAMP(6) LIMIT 1 FOR UPDATE', (rid,))
                if cursor.fetchone() is not None:
                    return api_error(409, 'Active checkouts must be released or '
                                          'expired before disabling checkout.')
            for key, enabled in sorted(changes.items()):
                if enabled and key not in current:
                    cursor.execute('INSERT INTO ' + table + '(repo_id,feature) VALUES (%s,%s)', (rid, key))
                elif not enabled and key in current:
                    cursor.execute('DELETE FROM ' + table + ' WHERE repo_id=%s AND feature=%s', (rid, key))
            cursor.execute('SELECT feature FROM ' + table + ' WHERE repo_id=%s ORDER BY feature', (rid,))
            return Response({'repo_id': rid, 'features': [row[0] for row in cursor.fetchall()]})
