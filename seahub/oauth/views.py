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
from seahub.utils import render_error, get_service_url
from seahub.utils.file_size import get_quota_from_string
from seahub.role_permissions.utils import get_enabled_role_permissions_by_role
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
    """Start the existing OAuth flow, optionally with a verified OIDC nonce."""
    if getattr(settings, 'CF_SSO_EAP_PROFILE_IDENTITY', False):
        from cloudfile_ext.sso.eap_oauth import login
        return login(request)

    oidc = getattr(request, '_cloudfile_oidc', False) is True
    nonce = None
    if oidc:
        try:
            from cloudfile_ext.v2.oidc import configuration
            configuration(settings)
            nonce = secrets.token_urlsafe(32)
        except Exception:
            logger.warning('SSO OIDC configuration unavailable')
            return render_error(request, _('Error, please contact administrator.'))
    session = OAuth2Session(client_id=CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URL)
    try:
        authorization_url, state = session.authorization_url(
            AUTHORIZATION_URL, **({'nonce': nonce} if oidc else {}))
    except Exception:
        logger.warning('SSO authorization request failed')
        return render_error(request, _('Error, please contact administrator.'))

    request.session['oauth_state'] = state
    request.session['oauth_protocol'] = 'oidc' if oidc else 'oauth2'
    if oidc:
        request.session['oauth_nonce'] = nonce
    else:
        request.session.pop('oauth_nonce', None)
    request.session['oauth_redirect'] = request.GET.get(auth.REDIRECT_FIELD_NAME, '/')
    return HttpResponseRedirect(authorization_url)


@oauth_check
def oauth_callback(request):
    """Authenticate through verified provider/sub -> exact business UID -> CE user.

    A mismatched/absent login_id is an authentication failure, NOT optional
    profile metadata. Never fall back to email or a stale social-auth account.
    """
    if getattr(settings, 'CF_SSO_EAP_PROFILE_IDENTITY', False):
        from cloudfile_ext.sso.eap_oauth import callback
        return callback(request)

    saved_state = request.session.pop('oauth_state', None)
    supplied_state = request.GET.get('state', '')
    protocol = request.session.pop('oauth_protocol', 'oauth2')
    nonce = request.session.pop('oauth_nonce', None)
    if (not isinstance(saved_state, str) or not saved_state
            or not isinstance(supplied_state, str) or not supplied_state
            or not secrets.compare_digest(saved_state, supplied_state)
            or protocol not in ('oauth2', 'oidc')
            or (protocol == 'oidc' and not nonce)):
        logger.warning('SSO state or protocol rejected')
        return render_error(request, _('Error, please contact administrator.'))

    session = OAuth2Session(client_id=CLIENT_ID, scope=SCOPE,
                            state=saved_state, redirect_uri=REDIRECT_URL)
    service_url = get_service_url().strip('/')
    try:
        token = session.fetch_token(
            TOKEN_URL, client_secret=CLIENT_SECRET,
            include_client_id=INCLUDE_CLIENT_ID,
            authorization_response=service_url + request.get_full_path())
        if 'user_id' in session._client.__dict__['token']:
            # Kept for legacy OAuth providers with a user_id parameter.
            user_id = session._client.__dict__['token']['user_id']
            user_info_resp = session.get(USER_INFO_URL + '?user_id=%s' % user_id)
        else:
            user_info_url = USER_INFO_URL
            if ACCESS_TOKEN_IN_URI:
                code = request.GET.get('code')
                user_info_url = USER_INFO_URL + '?access_token=%s&code=%s' % (
                    token['access_token'], code)
            user_info_resp = session.get(user_info_url)
        if user_info_resp.status_code != 200:
            raise ValueError('userinfo unavailable')
        user_info_json = user_info_resp.json()
        if not isinstance(user_info_json, dict):
            raise ValueError('invalid userinfo')
        if protocol == 'oidc':
            from cloudfile_ext.v2.oidc import configuration, verify_id_token
            issuer, jwks_uri = configuration(settings)
            claims = verify_id_token(token, issuer=issuer, jwks_uri=jwks_uri,
                                     client_id=CLIENT_ID, nonce=nonce)
            if claims['sub'] != user_info_json.get('sub'):
                raise ValueError('OIDC UserInfo subject mismatch')
    except Exception:
        logger.warning('SSO token or identity proof failed')
        return render_error(request, _('Error, please contact administrator.'))

    oauth_user_info = {}
    for oauth_attr, attr_tuple in OAUTH_ATTRIBUTE_MAP.items():
        required, user_attr = attr_tuple
        attr_value = user_info_json.get(oauth_attr, '')
        if attr_value:
            oauth_user_info[user_attr] = attr_value
        elif required:
            logger.warning('SSO required identity attribute missing')
            return render_error(request, _('Error, please contact administrator.'))

    subject = oauth_user_info.get('uid')
    login_id = oauth_user_info.get('login_id')
    if protocol == 'oidc' and 'userId' in claims and claims['userId'] != login_id:
        logger.warning('SSO OIDC business UID claim mismatch')
        return render_error(request, _('Error, please contact administrator.'))
    try:
        from cloudfile_ext.sso.uid_binding import bind_uid_account
        email = bind_uid_account(uid=login_id, provider=OAUTH_PROVIDER,
                                 subject=subject)
    except Exception:
        # UID account missing, collation alias, stale provider/sub binding,
        # inactive user or DB error all fail closed before session creation.
        logger.warning('SSO canonical UID binding rejected')
        return render_error(request, _('Error, please contact administrator.'))

    try:
        user = auth.authenticate(remote_user=email)
        if user is None or user.username != email or not user.is_active:
            raise ValueError('inactive or inconsistent authenticated account')
        if getattr(settings, 'CF_DIRECTORY_URL', None):
            from cloudfile_ext.v2.etech_directory import ensure_subject
            ensure_subject(login_id, email)
    except Exception:
        logger.warning('SSO UID subject or permissions unavailable')
        return render_error(request, _('Error, please contact administrator.'))

    request.user = user
    auth.login(request, user)
    oauth_id_token = token.get('id_token')
    if oauth_id_token:
        request.session['oauth_id_token'] = oauth_id_token
    else:
        request.session.pop('oauth_id_token', None)

    # Optional display metadata never changes ownership or login_id.
    name = oauth_user_info.get('name', '')
    contact_email = (oauth_user_info.get('contact_email', '')
                     or oauth_user_info.get('email', ''))
    try:
        profile = Profile.objects.get(user=email)
    except Profile.DoesNotExist:
        logger.warning('SSO profile missing after canonical UID binding')
    else:
        if isinstance(name, str) and name and (profile.nickname or '') != name.strip()[:64]:
            profile.nickname = name.strip()[:64]
            _save_profile_fields(profile, ['nickname'], email, 'nickname')
        if (isinstance(contact_email, str) and contact_email
                and (profile.contact_email or '').lower() != contact_email.strip().lower()):
            profile.contact_email = contact_email.strip()
            _save_profile_fields(profile, ['contact_email'], email, 'contact_email')

    if CUSTOM_GET_USER_ROLE:
        remote_role_value = oauth_user_info.get('role', '')
        if remote_role_value:
            role = custom_get_user_role(remote_role_value)
            ccnet_api.update_role_emailuser(email, role)
            role_quota = get_enabled_role_permissions_by_role(role)['role_quota']
            if role_quota:
                quota = get_quota_from_string(role_quota)
                seafile_api.set_role_quota(role, quota)

    api_token = get_api_token(request)
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
