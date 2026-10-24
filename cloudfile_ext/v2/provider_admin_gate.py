"""Request-time, fail-closed gate for enterprise-managed CE superadmins.

OFF by default. Native cfadmin remains independent. Once an operator enables
enterprise-admin synchronization for the entire external identity namespace,
a stored is_staff flag is *not* proof of current enterprise authority.
Do not use caches, mutable frontend roles or OAuth UserInfo to authorize it.
"""
import logging

from .provider_admin import trusted_super_admin

logger = logging.getLogger(__name__)
ROOT_NATIVE_NAMES = frozenset(('cfadmin', 'cfadmin@auth.local',
                               'cfadmin@etech.com'))


def is_native_root(username, uid):
    """Only the exact built-in CE identity can bypass enterprise authority."""
    # Some CE local root accounts have no Profile.login_id at all; a
    # *different* external UID on a reserved-looking username is not root.
    return (isinstance(username, str) and
            username.lower() in ROOT_NATIVE_NAMES and uid in (None, 'cfadmin'))


def provider_admin_allowed(username, uid, fetch):
    """Require a fresh verified server-side Directory response for THIS UID."""
    if is_native_root(username, uid):
        return True
    if not isinstance(uid, str) or not uid or not callable(fetch):
        return False
    try:
        subject = fetch(uid)
        return trusted_super_admin(subject, uid, require_claim=True) is True
    except Exception:
        return False


def mask_unverified_staff(user, *, enabled, uid_loader, fetch_subject):
    """Drop administrator privileges on this request, keep ordinary CE files.

    Calling this for each Session and Token authentication prevents existing
    credentials from retaining elevated authority after a Provider revocation
    or outage. It does NOT alter persisted CE EmailUser/AdminRole records.
    """
    if enabled is not True or not getattr(user, 'is_staff', False):
        return user
    username = getattr(user, 'username', None)
    uid = None
    try:
        uid = uid_loader(username)
        allowed = provider_admin_allowed(username, uid, fetch_subject)
    except Exception:
        allowed = False
    if not allowed:
        user.is_staff = False
        user.is_superuser = False
        user.admin_role = ''
    return user


def guard_authenticated_user(user):
    """Entrypoint for CE's Session and Token authentication seams."""
    from django.conf import settings
    if getattr(settings, 'CF_PROVIDER_ADMIN_SYNC_ENABLED', False) is not True:
        return user
    if not getattr(user, 'is_staff', False):
        return user

    def uid_loader(username):
        from seahub.profile.models import Profile
        profile = Profile.objects.get_profile_by_user(username)
        return profile.login_id if profile else None

    def fetch(uid):
        custom = getattr(settings, 'CF_PROVIDER_ADMIN_SUBJECT_FETCH', '')
        if custom:
            from django.utils.module_loading import import_string
            return import_string(custom)(uid)
        if not getattr(settings, 'CF_DIRECTORY_URL', ''):
            raise RuntimeError('enterprise admin Directory not configured')
        from .etech_directory import Directory
        return Directory().subject(uid)

    result = mask_unverified_staff(
        user, enabled=True, uid_loader=uid_loader, fetch_subject=fetch)
    if not result.is_staff:
        logger.warning('CloudFile administrator authority not verified; privilege denied')
    return result
