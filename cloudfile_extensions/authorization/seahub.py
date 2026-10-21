"""CE session-user authentication hook for the unregistered policy views."""
from ..common.errors import ContractError
from ..directory.native_state import NativeSubjectState
from .runtime import AuthenticatedPolicyActor


class SeahubPolicyAuthentication:
    def __init__(self, state_scope):
        if not callable(state_scope):
            raise ValueError("owned native state connection scope required")
        self.state_scope = state_scope

    def __call__(self, request):
        # Only the native auth middleware's session User is accepted here.
        # API tokens/delegation require their own authenticated, scoped adapter;
        # no Authorization/X-User-ID/contact-email fallback is implemented.
        from seahub.base.accounts import User
        from seahub.auth import SESSION_KEY, BACKEND_SESSION_KEY
        user = getattr(request, "user", None)
        if not isinstance(user, User) or user.is_authenticated is not True:
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated session is required", 401)
        session = getattr(request, "session", None)
        if session is None or session.get(SESSION_KEY) != user.username or not session.get(BACKEND_SESSION_KEY):
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated session is required", 401)
        if user.is_active is not True:
            raise ContractError("ACCESS_DENIED", "Policy account is not active", 403)
        with self.state_scope() as state:
            if not isinstance(state, NativeSubjectState):
                raise ContractError("POLICY_UNAVAILABLE", "Policy identity is unavailable", 503)
            actor = state.user_id(user.username)
            if not state.account_active(actor):
                raise ContractError("ACCESS_DENIED", "Policy account is not active", 403)
            return AuthenticatedPolicyActor(actor, user.username)
