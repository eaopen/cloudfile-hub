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
            # scoped Etech Directory before creating any native account.
            from .etech_directory import prepare_user
            from .errors import IdentityConflict, IdentityUnavailable
            try:
                username = prepare_user(uid)
            except IdentityConflict:
                return api_error(status.HTTP_409_CONFLICT, 'Native UID binding conflict.')
            except Exception:
                return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Trusted user preparation unavailable; sign in through SSO or restore Directory.')
        profile = Profile.objects.get_profile_by_user(username)
        if (profile is None or profile.login_id != uid
                or username.lower() in ('cfadmin@auth.local', 'cfadmin@etech.com')):
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
    """Prepare an exact trusted Etech entity as a native CE Group."""
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        external = request.data.get('external_group_id')
        if (not isinstance(external, str) or not external or external != external.strip()
                or external == 'role:' or len(external) > 225):
            return api_error(status.HTTP_400_BAD_REQUEST, 'External group ID required.')
        from .etech_directory import prepare_group, lookup_group
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
    """Etech PowerJob trigger; CloudFile reads only trusted entity catalog."""
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        if request.data:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Catalog trigger accepts no user-supplied snapshot.')
        if not request.user.admin_permissions.can_manage_group():
            return api_error(status.HTTP_403_FORBIDDEN, 'Native group management denied.')
        from .etech_directory import sync_entity_catalog
        try:
            result = sync_entity_catalog()
        except Exception:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                             'Trusted directory catalog reconciliation unavailable.')
        response = Response(result)
        response['Cache-Control'] = 'no-store'
        return response



class StorageReconcile(APIView):
    """Explicit admin-only mutation: idempotently register original Repo rows.

    Discovery itself stays in the native AdminLibraries GET endpoint.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)

    def post(self, request):
        from .native_discovery import reconcile_from_hub, inspect_from_hub
        if not request.user.admin_permissions.can_manage_library():
            return api_error(status.HTTP_403_FORBIDDEN, 'Permission denied.')
        ids = request.data.get('repo_ids', [])
        if not isinstance(ids, list) or len(ids) > 5000 or any(not isinstance(x, str) for x in ids):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid repo_ids list.')
        if len(ids) != len(set(ids)):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Duplicate repo_ids.')
        try:
            counts = reconcile_from_hub()
            states = inspect_from_hub(ids) if ids else {}
        except ValueError:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Invalid Repo UUID.')
        except Exception:
            return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'Native library registration unavailable.')
        response = Response({'registered': counts['registered'], 'statuses': states})
        response['Cache-Control'] = 'no-store'
        return response
