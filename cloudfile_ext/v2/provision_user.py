"""Trusted V2 just-in-time CE user pre-provisioning, without OAuth impersonation.

The Etech service may request a UID before the employee's first login, so a
library admin/share can be applied. This does NOT bind any OAuth subject or
issue a browser session. SSO later reuses the same exact native Profile.login_id.
"""
from .directory_client import DirectoryClient, configuration
from .errors import IdentityUnavailable
from .identity import text
from .memberships import validate_subject


def ensure_user(*, settings, uid, native_login):
    from django.db import connection
    from seahub.base.accounts import User
    from seahub.profile.models import Profile
    from .schema import database_lock

    uid = text(uid)
    native_login = text(native_login, 255)
    data = DirectoryClient(configuration(settings)).subject(uid)
    login, _ = validate_subject(data, uid)
    if data['status'] != 'active' or native_login != login.lower() + '@auth.local':
        raise IdentityUnavailable('trusted Directory UID/login mismatch')
    with database_lock(connection, 'identity:provision:' + uid):
        username = Profile.objects.get_username_by_login_id(uid)
        if username is None:
            # Native CE generates an opaque login and unusable local password.
            # No external SSO provider/sub is fabricated by this service.
            created = User.objects.create_oauth_user(email=None, password=None,
                                                     is_staff=False, is_active=True)
            username = created.username
            Profile.objects.add_or_update(username=username, login_id=uid,
                                          nickname=data['attributes'].get('display_name') or login)
        profile = Profile.objects.get_profile_by_user(username)
        if profile is None or profile.login_id != uid:
            raise IdentityUnavailable('ambiguous or changed UID binding')
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            raise IdentityUnavailable('native user disappeared') from None
        if not user.is_active:
            raise IdentityUnavailable('native user inactive')
        return dict(external_user_id=uid, login_id=uid, email=username, is_active=True)
