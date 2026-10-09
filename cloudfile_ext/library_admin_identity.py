"""Explicitly verified aliases for legacy library-administrator clients.

Business user IDs and OAuth subjects are separate identifiers. A reviewed
alias reuses the native account without changing its OAuth subject or email.
No employee/contact-email inference is allowed when no binding is configured.
"""
import re


def check_binding(alias, binding, profile, links, alias_owner):
    native = binding.get('native_user')
    employee = binding.get('employee_no')
    uid = binding.get('user_id')
    provider = binding.get('provider')
    subject = binding.get('oauth_subject')
    # A reviewed system-account binding changes presentation only; it never
    # confers staff status or content access. Keep all OAuth/UID checks below.
    valid_account = isinstance(employee, str) and (
        re.fullmatch(r'[0-9]{1,32}', employee) or
        (employee == 'admin' and binding.get('account_kind') == 'system'))
    if (not valid_account
            or alias != employee + '@auth.local' or not isinstance(uid, str)
            or not re.fullmatch(r'[0-9]{1,225}', uid) or not native
            or not provider or not subject or not profile
            or profile.user != native or profile.login_id not in (employee, uid)
            or links != [(native, provider, subject)]
            or alias_owner not in (None, native)):
        raise ValueError('Verified library administrator identity no longer matches')
    return native


def _configured():
    from django.conf import settings
    bindings = getattr(settings, 'CF_LIBRARY_ADMIN_IDENTITY_ALIASES', {})
    if not isinstance(bindings, dict):
        raise ValueError('Invalid library administrator identity configuration')
    return bindings


def _verified(alias, binding):
    from seahub.auth.models import SocialAuthUser
    from seahub.base.accounts import User
    from seahub.profile.models import Profile
    native = binding.get('native_user')
    profile = Profile.objects.get_profile_by_user(native)
    # Check both sides of the OAuth binding; a changed sub must fail closed.
    links = list(SocialAuthUser.objects.filter(
        username=native, provider=binding.get('provider')).values_list(
            'username', 'provider', 'uid'))
    if list(SocialAuthUser.objects.filter(
            provider=binding.get('provider'), uid=binding.get('oauth_subject'))
            .values_list('username', flat=True)) != [native]:
        raise ValueError('OAuth subject binding no longer matches')
    try:
        alias_owner = User.objects.get(email=alias).username
    except User.DoesNotExist:
        alias_owner = None
    native = check_binding(alias, binding, profile, links, alias_owner)
    if not User.objects.get(email=native).is_active:
        raise ValueError('Verified account is inactive')
    return native


def resolve_subject(subject, fallback=None):
    binding = _configured().get(subject)
    if binding is not None:
        return _verified(subject, binding)
    if fallback is None:
        from seahub.auth.utils import get_virtual_id_by_email
        fallback = get_virtual_id_by_email
    return fallback(subject)


def public_subject(native, fallback=None):
    matches = [(alias, binding) for alias, binding in _configured().items()
               if binding.get('native_user') == native]
    if len(matches) > 1:
        raise ValueError('Ambiguous library administrator aliases')
    if matches:
        alias, binding = matches[0]
        _verified(alias, binding)
        return alias
    if fallback is None:
        from seahub.profile.models import Profile
        fallback = Profile.objects.get_contact_email_by_user
    return fallback(native)
