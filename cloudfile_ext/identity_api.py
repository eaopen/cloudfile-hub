# -*- coding: utf-8 -*-
"""Administrator-only lookup and provisioning of external OAuth identities.

The caller supplies a verified provider UID and user attributes. CloudFile
does not fetch users from, or depend on, any particular external directory.
"""

from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings

from seahub.api2.authentication import TokenAuthentication
from seahub.api2.throttling import UserRateThrottle
from seahub.api2.utils import api_error

from cloudfile_ext.identity import unique_identity, AmbiguousSubject


class AdminExternalIdentityView(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser,)
    throttle_classes = (UserRateThrottle,)

    def get(self, request):
        external_id = (request.GET.get('external_user_id') or '').strip()
        if not external_id or len(external_id) > 225:
            return api_error(status.HTTP_400_BAD_REQUEST, 'external_user_id invalid.')

        from seahub.auth.models import SocialAuthUser
        from seahub.base.accounts import User
        from seahub.profile.models import Profile

        usernames = SocialAuthUser.objects.filter(uid=external_id).values_list(
            'username', flat=True)
        try:
            identity = unique_identity(usernames)
        except AmbiguousSubject:
            return api_error(status.HTTP_409_CONFLICT,
                             'External user ID maps to multiple accounts.')
        if identity is None:
            return Response({'external_user_id': external_id, 'found': False})

        try:
            user = User.objects.get(email=identity)
        except User.DoesNotExist:
            return api_error(status.HTTP_409_CONFLICT,
                             'SSO binding points to a missing account.')
        profile = Profile.objects.get_profile_by_user(identity)
        return Response({
            'external_user_id': external_id,
            'found': True,
            'email': identity,
            'login_id': profile.login_id if profile else '',
            'contact_email': profile.contact_email if profile else '',
            'is_active': user.is_active,
        })

    def post(self, request):
        """Create or reuse one SSO-only account and bind its stable UID.

        The trusted caller has already resolved the user in its own directory.
        No password is supplied and the account is never chosen by display name.
        """
        from seahub.auth.models import SocialAuthUser
        from seahub.base.accounts import User
        from seahub.profile.models import Profile, DuplicatedContactEmailError
        from seahub.auth.utils import get_virtual_id_by_email

        user_id = str(request.data.get('external_user_id') or '').strip()
        account = str(request.data.get('login_id') or '').strip()
        login_email = str(request.data.get('login_email') or '').strip().lower()
        contact_email = str(request.data.get('contact_email') or login_email).strip().lower()
        display_name = str(request.data.get('display_name') or '').strip()
        provider = (getattr(settings, 'OAUTH_PROVIDER', '')
                    or getattr(settings, 'OAUTH_PROVIDER_DOMAIN', ''))
        if not user_id or len(user_id) > 225 or not account or len(account) > 225 \
                or not login_email or '@' not in login_email or len(login_email) > 225 \
                or '@' not in contact_email or len(contact_email) > 225 \
                or len(display_name) > 64 or not provider:
            return api_error(status.HTTP_400_BAD_REQUEST, 'SSO user identity invalid.')

        linked = SocialAuthUser.objects.get_by_provider_and_uid(provider, user_id)
        if linked:
            native = linked.username
        else:
            by_login = Profile.objects.get_username_by_login_id(account)
            by_email = get_virtual_id_by_email(login_email)
            try:
                User.objects.get(email=by_email)
            except User.DoesNotExist:
                by_email = None
            by_contact = get_virtual_id_by_email(contact_email)
            try:
                User.objects.get(email=by_contact)
            except User.DoesNotExist:
                by_contact = None
            known = {value for value in (by_login, by_email) if value}
            if len(known) > 1 or (by_contact and known and by_contact not in known):
                return api_error(status.HTTP_409_CONFLICT,
                                 'Directory attributes belong to different accounts.')
            if by_contact and not known:
                return api_error(status.HTTP_409_CONFLICT,
                                 'Contact email exists without matching login ID.')
            native = next(iter(known)) if known else None
            if native is None:
                # OAuth accounts use an unusable local password. The provider
                # UID is bound below so first login selects this same account.
                try:
                    native = User.objects.create_oauth_user(
                        email=contact_email, password=None, is_active=True).username
                except DuplicatedContactEmailError:
                    return api_error(status.HTTP_409_CONFLICT,
                                     'Contact email belongs to another account.')
            profile = Profile.objects.get_profile_by_user(native)
            if profile and profile.login_id and profile.login_id != account:
                return api_error(status.HTTP_409_CONFLICT, 'SSO login ID does not match.')
            old_binding = SocialAuthUser.objects.filter(username=native,
                                                         provider=provider).first()
            if old_binding and old_binding.uid != user_id:
                return api_error(status.HTTP_409_CONFLICT, 'SSO provider UID does not match.')
            binding = SocialAuthUser.objects.add_if_not_exists(native, provider, user_id)
            if not binding:
                return api_error(status.HTTP_503_SERVICE_UNAVAILABLE, 'SSO binding failed.')
            if binding.username != native:
                return api_error(status.HTTP_409_CONFLICT, 'SSO UID belongs to another account.')

        try:
            user = User.objects.get(email=native)
        except User.DoesNotExist:
            return api_error(status.HTTP_409_CONFLICT, 'SSO binding has no native user.')
        if not user.is_active:
            return api_error(status.HTTP_409_CONFLICT, 'SSO user is inactive.')
        profile = Profile.objects.get_profile_by_user(native)
        if profile and profile.login_id and profile.login_id != account:
            return api_error(status.HTTP_409_CONFLICT, 'SSO login ID does not match.')
        other_login = Profile.objects.get_username_by_login_id(account)
        if other_login and other_login != native:
            return api_error(status.HTTP_409_CONFLICT, 'Login ID belongs to another account.')
        other_email = get_virtual_id_by_email(login_email)
        if other_email != login_email and other_email != native:
            return api_error(status.HTTP_409_CONFLICT, 'Email belongs to another account.')
        other_contact = get_virtual_id_by_email(contact_email)
        if other_contact != contact_email and other_contact != native:
            return api_error(status.HTTP_409_CONFLICT, 'Contact email belongs to another account.')
        try:
            Profile.objects.add_or_update(native, login_id=account,
                                          contact_email=contact_email,
                                          nickname=display_name or None)
        except DuplicatedContactEmailError:
            return api_error(status.HTTP_409_CONFLICT,
                             'Login ID or contact email belongs to another account.')
        return Response({'external_user_id': user_id, 'email': native,
                         'login_id': account, 'is_active': True})
