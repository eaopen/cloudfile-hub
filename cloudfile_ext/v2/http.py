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
