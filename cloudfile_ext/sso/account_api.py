"""Explicit EAP account-info presentation; native session identity is retained."""
from django.conf import settings
from seahub.api2.views import AccountInfo
from seahub.api2.utils import api_error
from cloudfile_ext.library_admin_identity import public_subject


class EmployeeAccountInfo(AccountInfo):
    def get(self, request, format=None):
        response = super().get(request, format=format)
        if getattr(settings, 'CF_EAP_ACCOUNT_INFO_IDENTITY_BRIDGE', False) is not True:
            return response
        try:
            # EAP compares this field to its employee identity. Only explicitly
            # reviewed aliases may change its presentation; native identity is
            # retained for all permission checks and returned for diagnostics.
            native = request.user.username
            alias = public_subject(native, fallback=lambda value: value)
            if alias != native:
                response.data['native_email'] = native
                response.data['email'] = alias
        except Exception:
            # A stale binding must refuse the identity check, never claim that
            # a session belongs to the caller's expected employee account.
            return api_error(503, 'Employee identity could not be verified.')
        return response
