"""Resolve verified OAuth/OIDC identities through the canonical CE login_id.

This adapter only links an externally verified provider subject to an existing
UID account. It never selects by email, employee number or nickname and never
rewrites an occupied login_id. Account preparation belongs to the Directory.
"""
import json


class UIDBindingError(ValueError):
    """Missing, ambiguous or conflicting native UID binding."""


def _identity(value, maximum):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise UIDBindingError('invalid identity')
    return value


def select_uid_owner(uid, profiles, bindings, *, provider, subject):
    """Pure selection policy: exact UID wins; a conflicting sub never redirects."""
    _identity(uid, 225)
    _identity(provider, 32)
    _identity(subject, 255)
    if len(profiles) != 1:
        raise UIDBindingError('canonical UID account not provisioned or ambiguous')
    username, saved_uid = profiles[0]
    if (not isinstance(username, str) or not username
            or saved_uid != uid
            or username.lower() in ('cfadmin@auth.local', 'cfadmin@etech.com')):
        raise UIDBindingError('canonical UID binding mismatch')
    if len(bindings) > 1:
        raise UIDBindingError('ambiguous provider subject')
    if bindings:
        linked_user, linked_provider, linked_sub = bindings[0]
        if (linked_user != username or linked_provider != provider
                or linked_sub != subject):
            raise UIDBindingError('provider subject conflicts with canonical UID')
    return username


def bind_uid_account(*, uid, provider, subject):
    """Atomically reuse an active UID account and persist one provider/sub link.

    Caller must verify the OAuth UserInfo or OIDC proof before calling this.
    No password, account, group grant or Profile.login_id is created here.
    """
    uid, provider, subject = (_identity(uid, 225),
                              _identity(provider, 32),
                              _identity(subject, 255))
    from django.db import IntegrityError, transaction
    from seahub.auth.models import SocialAuthUser
    from seahub.base.accounts import User
    from seahub.profile.models import Profile

    try:
        with transaction.atomic():
            profiles = list(Profile.objects.select_for_update().filter(
                login_id=uid).values_list('user', 'login_id'))
            bindings = list(SocialAuthUser.objects.select_for_update().filter(
                provider=provider, uid=subject).values_list('username', 'provider', 'uid'))
            username = select_uid_owner(uid, profiles, bindings,
                                        provider=provider, subject=subject)
            try:
                user = User.objects.get(email=username)
            except User.DoesNotExist:
                raise UIDBindingError('canonical native account missing') from None
            if (user.username != username or type(user.is_active) not in (bool, int)
                    or user.is_active != 1):
                raise UIDBindingError('canonical native account inactive or changed')
            if not bindings:
                # The native add() method swallows write failures: do not use it.
                SocialAuthUser.objects.create(
                    username=username, provider=provider, uid=subject,
                    extra_data=json.dumps({'userId': uid}, sort_keys=True))
            return username
    except IntegrityError:
        raise UIDBindingError('concurrent UID or provider binding conflict') from None
