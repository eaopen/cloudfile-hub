# -*- coding: utf-8 -*-

import os
import sys
import logging
import secrets
from django.db import IntegrityError, transaction
from django.http import HttpResponseRedirect
from django.utils.translation import gettext as _

from seaserv import seafile_api, ccnet_api

from seahub.api2.utils import get_api_token
from seahub import auth
from seahub.profile.models import Profile
from seahub.utils import is_valid_email, render_error, get_service_url
from seahub.utils.file_size import get_quota_from_string
from seahub.base.accounts import User
from seahub.role_permissions.utils import get_enabled_role_permissions_by_role
from seahub.auth.models import SocialAuthUser
import seahub.settings as settings

logger = logging.getLogger(__name__)


def _save_profile_fields(profile, fields, username, what):
    """Persist only the named columns; a unique-key conflict is a skipped
    metadata update, never a failed login.

    Profile keeps `user`, `login_id` and `contact_email` each unique, while the
    same person may legitimately own several historical identities (legacy
    employee-name account, EAP pre-created account, OAuth-created account). A
    whole-row save() therefore used to raise 1062 in the OAuth callback and turn
    a working login into HTTP 500 (CloudFile DEV, 2026-10-19).
    """
    try:
        with transaction.atomic():
            profile.save(update_fields=fields)
        return True
    except IntegrityError:
        logger.warning('OAuth profile %s conflict skipped (user=%s)', what, username)
        return False


LDAP_PROVIDER = getattr(settings, 'LDAP_PROVIDER', 'ldap')
SSO_LDAP_USE_SAME_UID = getattr(settings, 'SSO_LDAP_USE_SAME_UID', False)

try:
    current_path = os.path.dirname(os.path.abspath(__file__))
    seafile_conf_dir = os.path.join(current_path, '../../../../conf')
    sys.path.append(seafile_conf_dir)
    from seahub_custom_functions import custom_get_user_role
    CUSTOM_GET_USER_ROLE = True
except ImportError:
    CUSTOM_GET_USER_ROLE = False


ENABLE_OAUTH = getattr(settings, 'ENABLE_OAUTH', False)
if ENABLE_OAUTH:

    from requests_oauthlib import OAuth2Session

    if getattr(settings, 'OAUTH_ENABLE_INSECURE_TRANSPORT', False):
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Used for oauth workflow.
    CLIENT_ID = getattr(settings, 'OAUTH_CLIENT_ID', '')
    CLIENT_SECRET = getattr(settings, 'OAUTH_CLIENT_SECRET', '')
    AUTHORIZATION_URL = getattr(settings, 'OAUTH_AUTHORIZATION_URL', '')
    REDIRECT_URL = getattr(settings, 'OAUTH_REDIRECT_URL', '')
    TOKEN_URL = getattr(settings, 'OAUTH_TOKEN_URL', '')
    USER_INFO_URL = getattr(settings, 'OAUTH_USER_INFO_URL', '')
    SCOPE = getattr(settings, 'OAUTH_SCOPE', '')
    ACCESS_TOKEN_IN_URI = getattr(settings, 'OAUTH_ACCESS_TOKEN_IN_URI', False)
    INCLUDE_CLIENT_ID = getattr(settings, 'OAUTH_INCLUDE_CLIENT_ID', None)

    # Used for init an user for Seahub.
    OAUTH_PROVIDER = getattr(settings, 'OAUTH_PROVIDER', '')
    if not OAUTH_PROVIDER:
        OAUTH_PROVIDER = getattr(settings, 'OAUTH_PROVIDER_DOMAIN', '')
    OAUTH_ATTRIBUTE_MAP = getattr(settings, 'OAUTH_ATTRIBUTE_MAP', {})

ENABLE_CUSTOM_OAUTH = getattr(settings, 'ENABLE_CUSTOM_OAUTH', False)
if ENABLE_CUSTOM_OAUTH:
    try:
        current_path = os.path.dirname(os.path.abspath(__file__))
        conf_dir = os.path.join(current_path, '../../../../conf')
        sys.path.append(conf_dir)
        from seahub_custom_functions import custom_oauth_login, custom_oauth_callback
        ENABLE_CUSTOM_OAUTH = True
    except ImportError:
        ENABLE_CUSTOM_OAUTH = False


def oauth_check(func):
    """ Decorator for check if OAuth valid.
    """

    def _decorated(request):

        error = False
        if not ENABLE_OAUTH:
            logger.error('OAuth not enabled.')
            error = True
        else:
            if not CLIENT_ID or not CLIENT_SECRET or not AUTHORIZATION_URL \
                    or not REDIRECT_URL or not TOKEN_URL or not USER_INFO_URL \
                    or not SCOPE or not OAUTH_PROVIDER:
                logger.error('OAuth relevant settings invalid.')
                logger.error('CLIENT_ID_ASSIGNED: %s' % bool(CLIENT_ID))
                logger.error('AUTHORIZATION_URL_ASSIGNED: %s' % bool(AUTHORIZATION_URL))
                logger.error('REDIRECT_URL_ASSIGNED: %s' % bool(REDIRECT_URL))
                logger.error('TOKEN_URL_ASSIGNED: %s' % bool(TOKEN_URL))
                logger.error('USER_INFO_URL_ASSIGNED: %s' % bool(USER_INFO_URL))
                logger.error('SCOPE_ASSIGNED: %s' % bool(SCOPE))
                logger.error('OAUTH_PROVIDER_ASSIGNED: %s' % bool(OAUTH_PROVIDER))
                logger.error('CLIENT_SECRET_ASSIGNED: %s' % bool(CLIENT_SECRET))
                error = True

        if error:
            return render_error(request,
                                _('Error, please contact administrator.'))

        return func(request)

    return _decorated


# https://requests-oauthlib.readthedocs.io/en/latest/examples/github.html
# https://requests-oauthlib.readthedocs.io/en/latest/examples/google.html
@oauth_check
def oauth_login(request):
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    # Historical CF_SSO_EAP_PROFILE_IDENTITY is ignored. The current trusted
    # userId -> login_id checks below already serve the existing EAP /ssoAuth flow.
    # /oidc/login/ uses the same OAuth client but additionally requires a
    # verified ID Token. Keep the standalone V2 OIDC entrypoint independent.
    oidc_mode = getattr(request, '_cloudfile_oidc', False) is True
    nonce = None
    if oidc_mode:
        try:
            from cloudfile_ext.v2.oidc import configuration
            configuration(settings)
            nonce = secrets.token_urlsafe(32)
        except Exception:
            logger.warning('OIDC settings unavailable')
            return render_error(request, _('Error, please contact administrator.'))
    session = OAuth2Session(client_id=CLIENT_ID,
                            scope=SCOPE,
                            redirect_uri=REDIRECT_URL)

    try:
        authorization_url, state = session.authorization_url(
            AUTHORIZATION_URL, **({'nonce': nonce} if oidc_mode else {}))
    except Exception as e:
        logger.error(e)
        return render_error(request, _('Error, please contact administrator.'))

    request.session['oauth_state'] = state
    request.session['oauth_protocol'] = 'oidc' if oidc_mode else 'oauth2'
    if oidc_mode:
        request.session['oauth_nonce'] = nonce
    else:
        request.session.pop('oauth_nonce', None)
    request.session['oauth_redirect'] = request.GET.get(
        auth.REDIRECT_FIELD_NAME, '/')
    return HttpResponseRedirect(authorization_url)


# Step 2: User authorization, this happens on the provider.
@oauth_check
def oauth_callback(request):
    """ Step 3: Retrieving an access token.
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    # Reuse the normal OAuth callback for /ssoAuth. Ignore the retired EAP
    # bridge flag; keep state, subject, business UID and CE session validation.
    expected_state = request.session.pop('oauth_state', None)
    state = request.GET.get('state', '')
    protocol = request.session.pop('oauth_protocol', 'oauth2')
    nonce = request.session.pop('oauth_nonce', None)
    if (not isinstance(expected_state, str) or not expected_state
            or not isinstance(state, str) or not state
            or not expected_state.isascii() or not state.isascii()
            or not secrets.compare_digest(expected_state, state)
            or protocol not in ('oauth2', 'oidc')
            or (protocol == 'oidc' and (not isinstance(nonce, str) or not nonce))):
        logger.warning('OAuth state or protocol rejected')
        return render_error(request, _('Error, please contact administrator.'))
    session = OAuth2Session(client_id=CLIENT_ID,
                            scope=SCOPE,
                            state=expected_state,
                            redirect_uri=REDIRECT_URL)

    service_url = get_service_url().strip('/')

    try:
        token = session.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            include_client_id=INCLUDE_CLIENT_ID,
            authorization_response=service_url + request.get_full_path())

        if 'user_id' in session._client.__dict__['token']:
            # used for sjtu.edu.cn
            # https://xjq12311.gitbooks.io/sjtu-engtc/content/
            user_id = session._client.__dict__['token']['user_id']
            user_info_resp = session.get(USER_INFO_URL +
                                         '?user_id=%s' % user_id)
        else:
            user_info_url = USER_INFO_URL
            if ACCESS_TOKEN_IN_URI:
                code = request.GET.get('code')
                user_info_url = USER_INFO_URL + '?access_token=%s&code=%s' % (
                    token['access_token'], code)
            user_info_resp = session.get(user_info_url)

    except Exception as e:
        logger.error(e)
        return render_error(request, _('Error, please contact administrator.'))

    oauth_user_info = {}
    try:
        if user_info_resp.status_code != 200:
            raise ValueError('userinfo HTTP failure')
        user_info_json = user_info_resp.json()
        if not isinstance(user_info_json, dict):
            raise ValueError('invalid userinfo')
        if protocol == 'oidc':
            from cloudfile_ext.v2.oidc import configuration, verify_id_token, verified_oidc_subject
            issuer, jwks_uri = configuration(settings)
            claims = verify_id_token(token, issuer=issuer, client_id=CLIENT_ID,
                                     nonce=nonce, jwks_uri=jwks_uri)
            verified_oidc_subject(claims, user_info_json)
    except Exception:
        logger.warning('OAuth UserInfo/OIDC identity proof rejected')
        return render_error(request, _('Error, please contact administrator.'))
    for oauth_attr, attr_tuple in OAUTH_ATTRIBUTE_MAP.items():
        required, user_attr = attr_tuple
        attr_value = user_info_json.get(oauth_attr, '')
        if attr_value:
            oauth_user_info[user_attr] = attr_value
        elif required:
            # UserInfo can contain personal data; never dump it into logs.
            logger.warning('Required OAuth user attribute missing')
            return render_error(request, _('Error, please contact administrator.'))

    # A specifically mapped, trusted business userId is the canonical login_id.
    # Unmapped OAuth2 retains CE legacy compatibility; signed OIDC without
    # that mapping MUST use its verified sub, never an unverified email as UID.
    from cloudfile_ext.v2.oauth_identity import (
        trusted_uid_mapping, bind_existing_uid)
    strict_uid = trusted_uid_mapping(OAUTH_ATTRIBUTE_MAP)
    uid = (claims['sub'] if protocol == 'oidc' and not strict_uid
           else oauth_user_info.get('uid', '') or oauth_user_info.get('email', ''))
    if not uid:
        logger.warning('OAuth provider did not supply a stable user identifier')
        return render_error(request, _('Error, please contact administrator.'))
    if getattr(settings, 'CF_DIRECTORY_URL', '') and not strict_uid:
        # enterprise Directory deployments cannot reuse a legacy employee-number
        # mapping: that would overwrite the UID after a successful login.
        logger.warning('Directory login requires userId mapped to login_id')
        return render_error(request, _('Error, please contact administrator.'))
    if strict_uid:
        if (not isinstance(user_info_json.get('sub'), str) or not user_info_json.get('sub')
                or oauth_user_info.get('uid') != user_info_json['sub']):
            logger.warning('Trusted OAuth UID has no matching stable provider sub')
            return render_error(request, _('Error, please contact administrator.'))
        try:
            if protocol == 'oidc':
                # All strict OIDC UID bindings (not only enterprise Directory) require that
                # the business UID was asserted in the signed ID Token.
                # Never select an existing CE UID owner from UserInfo alone.
                from cloudfile_ext.v2.oidc import require_signed_business_uid
                require_signed_business_uid(claims, oauth_user_info['login_id'])
            if protocol == 'oidc' and getattr(settings, 'CF_DIRECTORY_URL', ''):
                # Only the trusted Directory integration can provision; pure
                # standalone OIDC still reuses an already-bound CE UID.
                from cloudfile_ext.v2.directory_adapter import provision_oidc_user
                email = provision_oidc_user(uid=oauth_user_info['login_id'],
                                           provider=OAUTH_PROVIDER, subject=oauth_user_info['uid'])
            else:
                email = bind_existing_uid(
                    uid=oauth_user_info['login_id'],
                    provider=OAUTH_PROVIDER, subject=oauth_user_info['uid'])
        except Exception:
            logger.warning('Trusted OAuth UID cannot resolve its native account')
            return render_error(request, _('Error, please contact administrator.'))
        is_new_user = False
    elif protocol == 'oidc':
        # An OIDC ID Token proves issuer + sub, NOT mailbox ownership.
        # Reuse only a provider/sub binding that an administrator or verified
        # provisioning flow already established. Never adopt a CE account by
        # matching the IdP's email, even if the address is verified there.
        oauth_user = SocialAuthUser.objects.get_by_provider_and_uid(OAUTH_PROVIDER, uid)
        if not oauth_user:
            logger.warning('OIDC subject has no trusted native account binding')
            return render_error(request, _('Error, new user registration is not allowed, please contact administrator.'))
        email = oauth_user.username
        is_new_user = False
    else:
        # Legacy OAuth2 remains compatible with existing email-based linkage.
        old_email = oauth_user_info.get('email', '')

        oauth_user = SocialAuthUser.objects.get_by_provider_and_uid(OAUTH_PROVIDER, uid)
        if not oauth_user and SSO_LDAP_USE_SAME_UID:
            oauth_user = SocialAuthUser.objects.get_by_provider_and_uid(LDAP_PROVIDER, uid)
            if oauth_user:
                SocialAuthUser.objects.add(oauth_user.username, OAUTH_PROVIDER, uid)
        if oauth_user:
            email = oauth_user.username
            is_new_user = False
        elif old_email:
            if not is_valid_email(str(old_email)):
                # In previous versions, if 'email' is not in mailbox format,
                # we combine 'email' and 'provider' to mailbox format.
                old_email = '%s@%s' % (str(old_email), OAUTH_PROVIDER)
            try:
                old_user = User.objects.get_old_user(old_email, OAUTH_PROVIDER, uid)
                email = old_user.username
                is_new_user = False
            except User.DoesNotExist:
                email = None
                is_new_user = True
        else:
            email = None
            is_new_user = True

    try:
        user = auth.authenticate(remote_user=email)
    except User.DoesNotExist:
        user = None
    except Exception as e:
        logger.error(e)
        return render_error(request, _('Error, please contact administrator.'))

    if not user:
        return render_error(request, _('Error, new user registration is not allowed, please contact administrator.'))

    if strict_uid or protocol == 'oidc':
        if (user.username != email or type(user.is_active) not in (bool, int)
                or user.is_active != 1):
            logger.warning('Trusted OAuth UID returned a different native user')
            return render_error(request, _('Error, please contact administrator.'))
        # For configured enterprise Directory deployments, refuse login when UID
        # membership cannot be refreshed. Do this BEFORE issuing any session.
        if getattr(settings, 'CF_DIRECTORY_URL', ''):
            try:
                from cloudfile_ext.v2.directory_adapter import ensure_subject
                ensure_subject(oauth_user_info['login_id'], email)
            except Exception:
                logger.warning('Trusted OAuth UID directory preparation failed')
                return render_error(request, _('Error, please contact administrator.'))

    email = user.username
    if is_new_user:
        SocialAuthUser.objects.add(email, OAUTH_PROVIDER, uid)

    # User is valid.  Set request.user and persist user in the session
    # by logging the user in.
    request.user = user
    auth.login(request, user)
    oauth_id_token = token.get('id_token')
    if oauth_id_token:
        request.session['oauth_id_token'] = oauth_id_token
    else:
        request.session.pop('oauth_id_token', None)

    # update user's profile
    name = oauth_user_info.get('name', '')
    contact_email = (oauth_user_info.get('contact_email', '')
                     or oauth_user_info.get('email', ''))
    login_id = oauth_user_info.get('login_id', '')

    # CloudFile: 三列各自唯一，整行 save() 一旦撞唯一键就把 OAuth 回调变成 500
    # （DEV 2026-10-19 实测：1062 profile_profile_contact_email_uniq）。这里只写
    # 本次真正变化的列，冲突降级为“跳过这条元数据”，登录本身不受影响。
    logger.info('OAuth profile sync: user=%s login_id=%s has_contact=%s',
                email, login_id, bool(contact_email))
    try:
        profile, profile_created = Profile.objects.get_or_create(user=email)
    except IntegrityError:
        profile = Profile.objects.filter(user=email).first()
    if profile is None:
        logger.warning('profile row unavailable for %s; profile sync skipped', email)
    else:
        if name and (profile.nickname or '') != name.strip()[:64]:
            profile.nickname = name.strip()[:64]
            _save_profile_fields(profile, ['nickname'], email, 'nickname')

        # 共享邮箱/已被他人占用的邮箱只是可选元数据：跳过即可，绝不据此合并主体。
        if contact_email and (profile.contact_email or '').lower() != contact_email.strip().lower():
            profile.contact_email = contact_email.strip()
            _save_profile_fields(profile, ['contact_email'], email, 'contact_email')

        # A trusted UID is authorization identity, not an optional metadata
        # sync. It was strictly bound BEFORE login and must never be rewritten.
        # Non-UID legacy OAuth keeps its previous compatibility metadata sync.
        if login_id and not strict_uid and protocol != 'oidc' and profile.login_id != login_id.strip():
            profile.login_id = login_id.strip()
            _save_profile_fields(profile, ['login_id'], email, 'login_id')

    if CUSTOM_GET_USER_ROLE:
        remote_role_value = oauth_user_info.get('role', '')
        if remote_role_value:
            role = custom_get_user_role(remote_role_value)

            # update user role
            ccnet_api.update_role_emailuser(email, role)

            # update user role quota
            role_quota = get_enabled_role_permissions_by_role(role)['role_quota']
            if role_quota:
                quota = get_quota_from_string(role_quota)
                seafile_api.set_role_quota(role, quota)

    # generate auth token for Seafile client
    api_token = get_api_token(request)

    # redirect user to home page
    response = HttpResponseRedirect(request.session.get('oauth_redirect', '/'))
    response.set_cookie('seahub_auth', email + '@' + api_token.key)
    response.set_cookie('via_oauth', 'true')
    return response


def custom_oauth_login_view(request):
    if not ENABLE_CUSTOM_OAUTH:
        return render_error(request, _('Feature is not enabled.'))

    if request.user.is_authenticated:
        # already authenticated
        redirect_url = request.GET.get(auth.REDIRECT_FIELD_NAME, settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(redirect_url)

    return custom_oauth_login(request)


def custom_oauth_callback_view(request):
    if not ENABLE_CUSTOM_OAUTH:
        return render_error(request, _('Feature is not enabled.'))

    return custom_oauth_callback(request)
