"""Native CE session reload only; never authenticate password or claims here.

Trusted guarded OIDC finalization may select this fixed backend after verified
identity and subject preparation. Adding it to settings alone cannot log in.
Resource endpoints must still perform their current subject/CE/C authorization.
"""


class CloudFileOIDCBackend:
    supports_object_permissions = False
    supports_anonymous_user = False

    def authenticate(self, **credentials):
        # No caller-provided userId, email, token or prepared DTO is an
        # authentication credential for this session reload backend.
        return None

    def get_user(self, username):
        from seahub.base.accounts import User
        from seahub.profile.models import Profile
        from django.core.exceptions import MultipleObjectsReturned
        if not isinstance(username, str) or not username or len(username) > 255 or "\x00" in username:
            return None
        try:
            user = User.objects.get(email=username)
            if user.username != username or not user.is_active:
                return None
            profile = Profile.objects.get(user=username)
            user_id = profile.login_id
            if (not isinstance(user_id, str) or not user_id or len(user_id) > 225
                    or "\x00" in user_id):
                return None
            # Do not reload a session through an ambiguous reverse business
            # identity; an email is not the business subject primary key.
            reverse = Profile.objects.get(login_id=user_id)
            if reverse.user != username:
                return None
            return user
        except (User.DoesNotExist, Profile.DoesNotExist, MultipleObjectsReturned):
            return None
