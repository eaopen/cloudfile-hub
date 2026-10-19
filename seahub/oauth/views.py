# -*- coding: utf-8 -*-

import os
import sys
import logging
import secrets
from urllib.parse import urlsplit
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
    oidc = getattr(request, '_cloudfile_oidc', False)
    request.session.pop('oauth_nonce', None)
    request.session['oauth_protocol'] = 'oidc' if oidc else 'oauth2'
    if oidc:
        from cloudfile_ext.v2.oidc import configuration
        try:
            configuration(settings)
            scopes = SCOPE.split() if isinstance(SCOPE, str) else SCOPE
            if 'openid' not in scopes:
                raise ValueError('OIDC requires openid scope')
        except Exception:
            return render_error(request, _('Error, please contact administrator.'))
        request.session['oauth_nonce'] = secrets.token_urlsafe(32)
    session = OAuth2Session(client_id=CLIENT_ID,
                            scope=SCOPE,
                            redirect_uri=REDIRECT_URL)

    try:
        extra = {'nonce': request.session['oauth_nonce']} if oidc else {}
        authorization_url, state = session.authorization_url(AUTHORIZATION_URL, **extra)
    except Exception as e:
        logger.error(e)
        return render_error(request, _('Error, please contact administrator.'))

    request.session['oauth_state'] = state
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
    state = request.session.pop('oauth_state', None)
    oidc = request.session.pop('oauth_protocol', 'oauth2') == 'oidc'
    nonce = request.session.pop('oauth_nonce', None)
    if (not isinstance(state, str) or not state or
            not secrets.compare_digest(state.encode(), request.GET.get('state', '').encode())):
        return render_error(request, _('Error, please contact administrator.'))
    session = OAuth2Session(client_id=CLIENT_ID,
                            scope=SCOPE,
                            state=state,
                            redirect_uri=REDIRECT_URL)

    # SERVICE_URL includes SITE_ROOT. get_full_path() already includes it too.
    service_origin = urlsplit(get_service_url())
    service_url = service_origin.scheme + '://' + service_origin.netloc

    try:
        token = session.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            include_client_id=INCLUDE_CLIENT_ID,
            authorization_response=service_url + request.get_full_path())

        verified_claims = None
        if oidc:
            from cloudfile_ext.v2.oidc import configuration, verify_id_token
            issuer, jwks_uri = configuration(settings)
            verified_claims = verify_id_token(token, issuer=issuer, client_id=CLIENT_ID,
                                              nonce=nonce, jwks_uri=jwks_uri)

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
        user_info_json = user_info_resp.json()
    except ValueError:
        return render_error(request, _('Error, please contact administrator.'))
    if user_info_resp.status_code != 200 or not isinstance(user_info_json, dict):
        return render_error(request, _('Error, please contact administrator.'))
    if oidc and user_info_json.get('sub') != verified_claims['sub']:
        return render_error(request, _('Error, please contact administrator.'))
    for oauth_attr, attr_tuple in OAUTH_ATTRIBUTE_MAP.items():
        required, user_attr = attr_tuple
        attr_value = user_info_json.get(oauth_attr, '')
        if attr_value:
            oauth_user_info[user_attr] = attr_value
        elif required:
            logger.error('Required user attr not found.')
            logger.error(user_info_json)
            return render_error(request, _('Error, please contact administrator.'))

    if oidc and (not isinstance(oauth_user_info.get('login_id'), str) or not oauth_user_info['login_id']):
        return render_error(request, _('Error, please contact administrator.'))
    uid = oauth_user_info.get('uid', '') or oauth_user_info.get('email', '')
    if not uid:
        logger.error('oauth user uid and email not found.')
        logger.error('user_info_json: %s' % user_info_json)
        return render_error(request, _('Error, please contact administrator.'))

    # compatible with old users via email
    old_email = oauth_user_info.get('email', '')

    oauth_user = SocialAuthUser.objects.get_by_provider_and_uid(OAUTH_PROVIDER, uid)
    # Reuse the native account already bound to the trusted business UID.
    # Employee names and contact emails are not account-binding keys.
    login_id = oauth_user_info.get('login_id', '')
    if login_id:
        from cloudfile_ext.v2.identity import text
        from cloudfile_ext.v2.errors import IdentityConflict
        try:
            text(login_id)
        except IdentityConflict:
            return render_error(request, _('Error, please contact administrator.'))
    profile_username = Profile.objects.get_username_by_login_id(login_id) if login_id else None
    if profile_username:
        profile = Profile.objects.get_profile_by_user(profile_username)
        # Native login_id lookups use a case-insensitive database collation.
        # A second login method must prove the exact same stable UID.
        if not profile or profile.login_id != login_id:
            return render_error(request, _('Error, please contact administrator.'))
    if oauth_user and login_id:
        profile = Profile.objects.get_profile_by_user(oauth_user.username)
        if ((profile_username and profile_username != oauth_user.username) or
                (profile and profile.login_id and profile.login_id != login_id)):
            return render_error(request, _('Error, please contact administrator.'))
    if not oauth_user and SSO_LDAP_USE_SAME_UID:
        oauth_user = SocialAuthUser.objects.get_by_provider_and_uid(LDAP_PROVIDER, uid)
        if oauth_user:
            SocialAuthUser.objects.add(oauth_user.username, OAUTH_PROVIDER, uid)
    if oauth_user:
        email = oauth_user.username
        is_new_user = False
    elif profile_username:
        email = profile_username
        is_new_user = True  # Add the OAuth binding after native account authentication.
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
    contact_email = oauth_user_info.get('contact_email', '')
    login_id = oauth_user_info.get('login_id', '')

    # Preserve the reviewed DEV Profile conflict handling in the clean build:
    # optional contact metadata must not turn a valid SSO callback into HTTP 500.
    # Account/UID binding checks and subject refresh still run independently.
    from django.db import IntegrityError, transaction

    profile = Profile.objects.get_profile_by_user(email)
    if not profile:
        profile = Profile(user=email)
        try:
            with transaction.atomic():
                profile.save()
        except IntegrityError:
            profile = Profile.objects.get_profile_by_user(email)
    if profile is None:
        logger.error('profile unavailable for %s; profile update skipped', email)
    else:
        logger.info('OAuth profile sync: user=%s login_id=%s has_contact=%s',
                    email, login_id, bool(contact_email))
        if name:
            profile.nickname = name.strip()[:64]
            try:
                with transaction.atomic():
                    profile.save(update_fields=['nickname'])
            except IntegrityError:
                logger.warning('profile nickname write skipped (user=%s)', email)
        if contact_email:
            value = contact_email.strip()
            if value and (profile.contact_email or '').lower() != value.lower():
                taken = Profile.objects.filter(contact_email__iexact=value).exclude(pk=profile.pk).exists()
                if taken:
                    logger.warning('shared OAuth contact email skipped (user=%s)', email)
                else:
                    profile.contact_email = value
                    try:
                        with transaction.atomic():
                            profile.save(update_fields=['contact_email'])
                    except IntegrityError:
                        logger.warning('concurrent contact email conflict skipped (user=%s)', email)
        if login_id:
            value = login_id.strip()
            if value and profile.login_id != value:
                try:
                    with transaction.atomic():
                        profile.login_id = value
                        profile.save(update_fields=['login_id'])
                except IntegrityError:
                    logger.warning('login_id already bound elsewhere; kept existing (user=%s uid=%s)',
                                   email, value)
    # Etech remains the master login. For its CloudFile SSO session, verify
    # current UID memberships before permitting this native session to proceed.
    # CE-only deployments with no Directory URL retain original native flow.
    if getattr(settings, 'CF_DIRECTORY_URL', ''):
        try:
            if not login_id:
                raise ValueError('stable UID missing')
            from cloudfile_ext.v2.etech_directory import ensure_subject
            ensure_subject(login_id, email)
        except Exception:
            logger.error('CloudFile SSO subject preparation unavailable')
            auth.logout(request)
            return render_error(request, _('Error, please contact administrator.'))

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
