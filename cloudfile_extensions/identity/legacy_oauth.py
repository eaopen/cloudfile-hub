"""V2 legacy-OAuth adapter: attach a trusted Etech UID to its native CE account.

The existing OAuth protocol stays upstream. This adapter is only used when
the configured IdP maps a trusted userId claim to Profile.login_id. Unmapped
legacy OAuth logins remain on the CE compatibility path.
"""
import json


class UIDBindingError(ValueError):
    """Untrusted, missing, disabled or conflicting UID / subject binding."""


def trusted_uid_mapping(attribute_map):
    """Recognize an explicitly configured business UID claim, not an email."""
    return isinstance(attribute_map, dict) and attribute_map.get("userId") in (
        (True, "login_id"), (False, "login_id"))


def _text(value, maximum):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or value != value.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise UIDBindingError("invalid identity")
    return value


def choose_uid_owner(uid, profiles, bindings, *, provider, subject):
    """No email/employee fallback; an existing subject cannot change owners."""
    _text(uid, 225)
    _text(provider, 32)
    _text(subject, 255)
    if len(profiles) != 1:
        raise UIDBindingError("missing or ambiguous canonical UID")
    username, stored_uid = profiles[0]
    if (not isinstance(username, str) or not username or stored_uid != uid
            or username.lower() in ("cfadmin@auth.local", "cfadmin@etech.com")):
        raise UIDBindingError("canonical UID mismatch")
    if len(bindings) > 1:
        raise UIDBindingError("ambiguous provider subject")
    if bindings and bindings[0] != (username, provider, subject):
        raise UIDBindingError("provider subject belongs to a different account")
    return username


def bind_existing_uid(*, uid, provider, subject):
    """Use the existing UID owner and add only a missing provider/sub mapping.

    OAuth state and UserInfo must be verified by the caller, and userId must be
    provisioned by a trusted Etech/IdP source. Never create/migrate native users.
    """
    uid, provider, subject = (_text(uid, 225), _text(provider, 32),
                              _text(subject, 255))
    from django.db import IntegrityError, transaction
    from seahub.auth.models import SocialAuthUser
    from seahub.base.accounts import User
    from seahub.profile.models import Profile

    try:
        with transaction.atomic():
            profiles = list(Profile.objects.select_for_update().filter(
                login_id=uid).values_list("user", "login_id"))
            bindings = list(SocialAuthUser.objects.select_for_update().filter(
                provider=provider, uid=subject).values_list("username", "provider", "uid"))
            username = choose_uid_owner(uid, profiles, bindings,
                                        provider=provider, subject=subject)
            try:
                user = User.objects.get(email=username)
            except User.DoesNotExist:
                raise UIDBindingError("native UID account missing") from None
            if (user.username != username or type(user.is_active) not in (bool, int)
                    or user.is_active != 1):
                raise UIDBindingError("native UID account inactive or changed")
            if not bindings:
                # CE Manager.add() swallows integrity errors; use the ORM directly.
                SocialAuthUser.objects.create(
                    username=username, provider=provider, uid=subject,
                    extra_data=json.dumps({"userId": uid}, sort_keys=True))
            return username
    except IntegrityError:
        raise UIDBindingError("concurrent provider/UID conflict") from None
