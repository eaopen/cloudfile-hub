"""Read-only CE account adapter; userId maps exclusively through Profile.login_id.

Does not create/activate users, merge email aliases, or grant library membership.
Final native operations must still recheck account state under their coordinator.
"""

from ..common.errors import ContractError
from ..common.validation import identifier


class NativeAccounts:
    def __init__(self, *, profiles=None, users=None):
        if profiles is None:
            from seahub.profile.models import Profile
            profiles = Profile
        if users is None:
            from seahub.base.accounts import User
            users = User
        self.profiles = profiles
        self.users = users

    def by_username(self, username):
        identifier(username)
        try:
            account = self.users.objects.get(email=username)
        except self.users.DoesNotExist:
            raise ContractError("IDENTITY_NOT_FOUND", "Native account does not exist", 404) from None
        except Exception:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native account state is unavailable", 503) from None
        if account.username != username:
            raise ContractError("IDENTITY_CONFLICT", "Native account identity does not match", 409)
        return account

    def by_user_id(self, user_id):
        identifier(user_id, maximum=225)
        try:
            profile = self.profiles.objects.filter(login_id=user_id).first()
        except Exception:
            raise ContractError("IDENTITY_UNAVAILABLE", "Native identity mapping is unavailable", 503) from None
        if profile is None:
            raise ContractError("IDENTITY_NOT_FOUND", "Business identity has not been bound", 404)
        # MySQL's default collation can match another case/accent. Never infer an
        # account from contact_email, employee number, nickname or query fallback.
        if profile.login_id != user_id:
            raise ContractError("IDENTITY_CONFLICT", "Business identity mapping does not match", 409)
        return self.by_username(profile.user)

    def _active(self, lookup, identity):
        try:
            account = lookup(identity)
        except ContractError as error:
            if error.status == 404:
                return False
            raise
        # CE RPC uses boolean or integer 0/1. Reject truthy strings or unexpected
        # values instead of allowing a malformed RPC adapter to activate a user.
        return type(account.is_active) in (bool, int) and account.is_active == 1

    def active_user_id(self, user_id):
        return self._active(self.by_user_id, user_id)

    def active_username(self, username):
        return self._active(self.by_username, username)
