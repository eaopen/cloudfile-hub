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

from cloudfile_ext.identity import unique_identity, AmbiguousSubject, provisioning_provider


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
        # Directory business IDs are not OAuth sub values; retain both bindings
        # so permission synchronization cannot break an existing SSO login.
        try:
            provider = provisioning_provider(request.data.get('identity_source'), provider)
        except ValueError:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Identity source invalid.')
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
            # 2026-10-14：不再用 contact_email 参与身份判定。
            # 原因：eTech 目录存在不同账号共用同一邮箱（实测生产 7 组），而其余账号
            # 「共享邮箱就该跳过」而非「拒绝建号」。原实现把 by_contact 混进身份一致性
            # 校验，会让共享邮箱者（例如同一外部邮箱下的三个账号）永远建不了号。
            # 邮箱归属改由下面的 update_optional_contact_email 决定：
            # 空/已被他人占用 → 跳过并告警，身份仍按 login_id / OAuth sub 建立。
            known = {value for value in (by_login, by_email) if value}
            if len(known) > 1:
                return api_error(status.HTTP_409_CONFLICT,
                                 'Directory attributes belong to different accounts.')
            native = next(iter(known)) if known else None
            if native is None:
                # 2026-10-14：账号名统一取 EAP 下发的 login_email（= 工号@auth.local）。
                # 不能再走 create_oauth_user：它写死 gen_user_virtual_id() 作 username
                # （seahub/base/accounts.py），账号名永远是不透明虚拟 id，于是 EAP 的
                # account-info.email == 工号@auth.local 校验只能靠别名白名单桥接兜着。
                # 与 OAuth 登录路径（cloudfile_ext/sso/eap_oauth.provision、
                # cloudfile_extensions/identity/jit）使用同一命名规则。
                # OAuth 账号用不可用口令；provider UID 在下面绑定，首次登录选中同一账号。
                if Profile.objects.filter(user=login_email).exists():
                    return api_error(status.HTTP_409_CONFLICT,
                                     'Account name is already taken.')
                try:
                    User.objects.get(email=login_email)
                except User.DoesNotExist:
                    pass
                else:
                    return api_error(status.HTTP_409_CONFLICT,
                                     'Account name is already taken.')
                new_user = User(email=login_email)
                new_user.is_staff, new_user.is_active = False, True
                new_user.set_unusable_password()
                # 原生 RPC 写入不在 Profile 事务内：建号失败绝不能留下"绑定成功"的假象。
                if new_user.save() != 0:
                    return api_error(status.HTTP_503_SERVICE_UNAVAILABLE,
                                     'Account creation failed.')
                native = login_email
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
        try:
            Profile.objects.add_or_update(native, login_id=account,
                                          nickname=display_name or None)
        except DuplicatedContactEmailError:
            return api_error(status.HTTP_409_CONFLICT,
                             'Login ID belongs to another account.')
        # 2026-10-14：contact_email 走「共享邮箱就跳过」的降级语义，不再 fail-closed。
        # 原因：eTech 目录存在不同账号共用同一邮箱（实测生产 7 组）且大量为空，而
        # Profile.contact_email 是上游唯一索引（2019 起，且上游按它反查账号）。
        # 身份由 login_id / OAuth sub 决定，邮箱只是联系资料 —— 绝不能因为目录里的
        # 共享邮箱让建号与同步整体 409 失败。复用 OAuth 登录路径同一份实现
        # （cloudfile_ext/sso/oauth_profile.update_optional_contact_email：
        # 空值/已属他人/并发冲突都只跳过并告警）。EAP 侧的确定性裁决见
        # CloudDirectorySnapshotService.authoritativeContactEmail。
        from cloudfile_ext.sso.oauth_profile import update_optional_contact_email
        profile = Profile.objects.get_profile_by_user(native)
        if profile is not None:
            update_optional_contact_email(profile, contact_email)
        return Response({'external_user_id': user_id, 'email': native,
                         'login_id': account,
                         'contact_email': (profile.contact_email or '') if profile else '',
                         'is_active': True})
