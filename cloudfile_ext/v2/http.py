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
                or request.data.get('login_id') != uid):
            return api_error(status.HTTP_400_BAD_REQUEST, 'Stable UID required.')
        username = Profile.objects.get_username_by_login_id(uid)
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
        if profile is None or profile.login_id != uid:
            return api_error(status.HTTP_409_CONFLICT, 'Native UID binding conflict.')
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return api_error(status.HTTP_404_NOT_FOUND, 'Native user not found.')
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
