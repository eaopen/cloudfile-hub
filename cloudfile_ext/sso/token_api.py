"""Opt-in token compatibility through the existing extension URL seam."""
from django.conf import settings
from rest_framework.response import Response
from seahub.api2.endpoints.admin.generate_user_auth_token import AdminGenerateUserAuthToken
from seahub.api2.utils import api_error, get_token_v1
from seahub.base.accounts import User
from cloudfile_ext.library_admin_identity import resolve_subject
from .token_identity import resolve_employee_token


class EmployeeTokenView(AdminGenerateUserAuthToken):
    def post(self, request):
        # Require an explicit boolean: the string 'false' must not enable a
        # privileged bridge. Native administrator authentication is inherited.
        if getattr(settings, 'CF_EAP_ADMIN_TOKEN_IDENTITY_BRIDGE', False) is not True:
            return super().post(request)
        try:
            # Reuse reviewed aliases before native lookup so collisions or stale
            # OAuth bindings cannot silently issue a different account's token.
            native = resolve_subject(request.data.get('email'), fallback=lambda _: None)
            if native is None:
                response = super().post(request)
                if response.status_code != 404:
                    return response
                native = resolve_employee_token(request.data.get('email'))
            user = User.objects.get(email=native)
            if user.username != native or not user.is_active:
                raise ValueError('Inactive or changed account')
            token = get_token_v1(user.username)
        except Exception:
            # Never serialize client exceptions: they can contain credentials.
            return api_error(503, 'Employee identity could not be verified.')
        return Response({'token': token.key})
