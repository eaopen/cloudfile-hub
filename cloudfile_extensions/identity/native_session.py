"""Actual CE non-local-MFA finalizer, explicitly unregistered pending MFA work."""
from django.conf import settings
from django.http import HttpResponseRedirect

from ..common.errors import ContractError
from .login import PendingLogin, PreparedLogin
from .native_backend import CloudFileOIDCBackend
from .runtime import LoginRuntime
from .session_guard import prepared_session_guard


BACKEND = "cloudfile_extensions.identity.native_backend.CloudFileOIDCBackend"


class NativeOIDCSession:
    def complete(self, request, runtime, *, state, code, binding):
        if not isinstance(runtime, LoginRuntime) or not request.is_secure():
            raise ValueError("actual owned login runtime and HTTPS request required")
        if BACKEND not in settings.AUTHENTICATION_BACKENDS:
            raise ContractError("IDENTITY_UNAVAILABLE", "OIDC native session backend is not configured", 503)
        # Only this actual OIDC validation establishes a login identity. The
        # caller cannot submit a prepared DTO as an authentication credential.
        prepared = runtime.login.complete(state=state, code=code, binding=binding)
        if isinstance(prepared, PendingLogin):
            return prepared
        if not isinstance(prepared, PreparedLogin):
            raise ContractError("IDENTITY_UNAVAILABLE", "OIDC login preparation is unavailable", 503)
        from seahub.auth import login as auth_login
        from seahub.auth.models import AnonymousUser
        from seahub.utils.two_factor_auth import two_factor_auth_enabled
        user = CloudFileOIDCBackend().get_user(prepared.username)
        if user is None:
            raise ContractError("ACCESS_DENIED", "OIDC native account is unavailable", 403)
        # Do not silently treat IdP authentication as completion of CE local
        # OTP. Deferred OTP needs its own browser-bound proof and final guard.
        if two_factor_auth_enabled(user):
            raise ContractError("MFA_REQUIRED", "Native second-factor completion is required", 403)
        preparation = runtime.preparation(prepared.user_id)
        attempted = False
        try:
            with prepared_session_guard(preparation, prepared):
                runtime.browser.assert_active(binding)
                attempted = True
                request.session.flush()
                request.session["remember_me"] = False
                user.backend = BACKEND
                auth_login(request, user)
                request.session.save()
                response = HttpResponseRedirect(prepared.redirect)
                runtime.browser.clear(binding, response)
            return response
        except Exception:
            if attempted:
                # No response/cookie is returned before guard success. Remove
                # a persisted session on final epoch/expiry/storage failure.
                request.user = AnonymousUser()
                try:
                    request.session.flush()
                except Exception:
                    raise ContractError("IDENTITY_UNAVAILABLE", "Session cleanup is unavailable", 503) from None
            raise
