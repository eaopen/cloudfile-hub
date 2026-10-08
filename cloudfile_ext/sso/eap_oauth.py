"""EAP identity contract for the deployed Seahub OAuth entry point.

The provider/sub binding is retained; Profile.login_id is the business UID.
This opt-in bridge exists because the legacy callback otherwise creates opaque
accounts before validating the business identity and overwrites login_id later.
"""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import secrets
import time
from types import SimpleNamespace


class IdentityConflict(ValueError):
    pass


def identity_pair(info):
    uid, employee = info.get('userId'), info.get('preferred_username')
    if (not isinstance(uid, str) or not uid.isascii() or not uid.isdigit()
            or len(uid) > 225 or not isinstance(employee, str) or not employee
            or len(employee) > 200 or employee.lower() == 'cfadmin'
            or not all(c.isascii() and (c.isalnum() or c in '._-') for c in employee)):
        raise IdentityConflict('invalid EAP identity')
    return uid, employee


def choose_native(uid, employee, social_username, social_profile, uid_profiles):
    """Only verified provider/sub or an exact UID can reuse an existing account."""
    if len(uid_profiles) > 1:
        raise IdentityConflict('ambiguous UID')
    native = uid_profiles[0][0] if uid_profiles else None
    if uid_profiles and uid_profiles[0][1] != uid:
        raise IdentityConflict('UID collation alias')
    if social_username:
        # An existing stable sub plus the current EAP directory proves a legacy
        # employee login_id upgrade. Employee-only lookups never prove ownership.
        if social_profile and social_profile[1] not in (None, '', employee, uid):
            raise IdentityConflict('changed UID requires explicit rebind')
        if native and native != social_username:
            raise IdentityConflict('sub and UID disagree')
        native = social_username
    if native and native.lower() in ('cfadmin@etech.com', 'cfadmin@auth.local'):
        raise IdentityConflict('system administrator is not an employee')
    return native


@contextmanager
def identity_lock(provider, uid, employee, subject):
    from django.db import connection
    names = sorted({'cf:eap:' + hashlib.sha256((connection.settings_dict['NAME'] + ':' + key).encode()).hexdigest()[:48]
                    for key in ('uid:' + uid, 'employee:' + employee.lower(), 'sub:' + provider + ':' + subject)})
    held = []
    try:
        with connection.cursor() as cursor:
            for name in names:
                cursor.execute('SELECT GET_LOCK(%s, 5)', [name])
                if cursor.fetchone()[0] != 1:
                    raise IdentityConflict('identity busy')
                held.append(name)
        yield
    finally:
        with connection.cursor() as cursor:
            for name in reversed(held):
                cursor.execute('SELECT RELEASE_LOCK(%s)', [name])


def provision(provider, info):
    from django.conf import settings
    from django.db import transaction
    from seahub.auth.models import SocialAuthUser
    from seahub.base.accounts import User
    from seahub.profile.models import Profile
    from cloudfile_ext.registry import registry
    from . import directory
    uid, employee = identity_pair(info)
    subject = info['sub']
    # Check the same authenticated directory used by membership reconciliation.
    source = directory.active(registry)
    context = source.context_for_user_id(uid)
    if (context['status'] != 'active'
            or context['attributes'].get('employee_no') != employee):
        raise IdentityConflict('directory identity mismatch')
    with identity_lock(provider, uid, employee, subject), transaction.atomic():
        bindings = list(SocialAuthUser.objects.select_for_update().filter(provider=provider, uid=subject))
        if len(bindings) > 1 or (bindings and (bindings[0].provider != provider or bindings[0].uid != subject)):
            raise IdentityConflict('ambiguous subject')
        existing = bindings[0].username if bindings else None
        social_profile = list(Profile.objects.select_for_update().filter(user=existing).values_list('user', 'login_id')) if existing else []
        if len(social_profile) > 1 or (social_profile and social_profile[0][0] != existing):
            raise IdentityConflict('ambiguous native profile')
        uid_profiles = list(Profile.objects.select_for_update().filter(login_id=uid).values_list('user', 'login_id'))
        native = choose_native(uid, employee, existing, social_profile[0] if social_profile else None, uid_profiles)
        if native:
            user = User.objects.get(email=native)
            if user.username != native or not user.is_active:
                raise IdentityConflict('inactive native account')
        else:
            if not getattr(settings, 'OAUTH_CREATE_UNKNOWN_USER', False):
                raise IdentityConflict('provisioning disabled')
            native = employee + '@auth.local'
            if Profile.objects.filter(user=native).exists():
                raise IdentityConflict('employee account collision')
            try:
                User.objects.get(email=native)
            except User.DoesNotExist:
                pass
            else:
                raise IdentityConflict('native account collision')
            user = User(email=native)
            user.is_staff, user.is_active = False, True
            user.set_unusable_password()
            # Native RPC writes are outside the Profile transaction; a failed
            # creation must never leave a successful OIDC/Profile binding.
            if user.save() != 0:
                raise IdentityConflict('native account creation failed')
        profile, _ = Profile.objects.get_or_create(user=native)
        profile.login_id = uid
        profile.nickname = str(info.get('name') or employee)[:64]
        profile.save()
        if not bindings:
            # Do not use Manager.add(): it swallows uniqueness/storage errors.
            SocialAuthUser.objects.create(username=native, provider=provider, uid=subject,
                                          extra_data=json.dumps({'userId': uid}))
        from .oauth_profile import update_optional_contact_email
        update_optional_contact_email(profile, info.get('email'))
    return user


class JsonClient:
    """Fixed deployment URLs only; bounded replies and no ambient proxy/netrc."""
    def get(self, url, headers=None):
        import requests
        from cloudfile_extensions.common.http import read_json_response
        with requests.Session() as client:
            client.trust_env = False
            return read_json_response(client.get(url, headers=headers, timeout=(3, 10),
                                      allow_redirects=False, stream=True), maximum_bytes=65536)


def login(request):
    from django.conf import settings
    from django.http import HttpResponseRedirect
    from requests_oauthlib import OAuth2Session
    verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    session = OAuth2Session(settings.OAUTH_CLIENT_ID, scope=settings.OAUTH_SCOPE,
                           redirect_uri=settings.OAUTH_REDIRECT_URL)
    url, state = session.authorization_url(settings.OAUTH_AUTHORIZATION_URL,
        nonce=nonce, code_challenge=challenge, code_challenge_method='S256')
    request.session['cf_eap_oidc'] = dict(state=state, nonce=nonce, verifier=verifier, issued=time.time())
    # Only local paths can be used as post-login destinations.
    target = request.GET.get('next', settings.SITE_ROOT)
    request.session['oauth_redirect'] = target if target.startswith('/') and not target.startswith('//') and '\\' not in target else settings.SITE_ROOT
    return HttpResponseRedirect(url)


def callback(request):
    from django.conf import settings
    from django.http import HttpResponseRedirect
    from requests_oauthlib import OAuth2Session
    from seahub import auth
    from seahub.api2.utils import get_api_token
    from seahub.utils import render_error
    from cloudfile_extensions.identity.oidc import IDTokenValidator, SigningKeys
    try:
        flow = request.session.pop('cf_eap_oidc', None)
        state = request.GET.get('state', '')
        if (not flow or not state or not hmac.compare_digest(flow['state'], state)
                or not 0 <= time.time() - flow['issued'] <= 300 or not request.GET.get('code')):
            raise IdentityConflict('expired or invalid OIDC state')
        with OAuth2Session(settings.OAUTH_CLIENT_ID, state=state,
                           redirect_uri=settings.OAUTH_REDIRECT_URL) as session:
            session.trust_env = False
            token = session.fetch_token(settings.OAUTH_TOKEN_URL,
                code=request.GET['code'], client_secret=settings.OAUTH_CLIENT_SECRET,
                code_verifier=flow['verifier'], include_client_id=True, timeout=(3, 10), allow_redirects=False)
        info = JsonClient().get(settings.OAUTH_USER_INFO_URL,
                               headers={'Authorization': 'Bearer ' + token['access_token']})
        config = SimpleNamespace(issuer=settings.CF_SSO_EAP_OIDC_ISSUER,
                                 client_id=settings.OAUTH_CLIENT_ID, user_id_claim='userId')
        validated = IDTokenValidator(config, SigningKeys(settings.CF_SSO_EAP_OIDC_JWKS_URL, client=JsonClient(),
            allow_http=getattr(settings, "OAUTH_ENABLE_INSECURE_TRANSPORT", False) is True)).validate(
            token['id_token'], nonce=flow['nonce'], access_token=token['access_token'], userinfo=info)
        if validated['userId'] != info.get('userId'):
            raise IdentityConflict('missing business UID')
        user = provision(settings.OAUTH_PROVIDER, info)
        user.backend = 'seahub.oauth.backends.OauthRemoteUserBackend'
        request.user = user
        # Profile is committed before the login signal refreshes UID permissions.
        auth.login(request, user)
        request.session['oauth_id_token'] = token['id_token']
        api_token = get_api_token(request)
        response = HttpResponseRedirect(request.session.get('oauth_redirect', settings.SITE_ROOT))
        response.set_cookie('seahub_auth', user.username + '@' + api_token.key)
        response.set_cookie('via_oauth', 'true')
        return response
    except Exception:
        import logging
        logging.getLogger(__name__).warning('EAP OIDC login refused; identity or provider unavailable')
        return render_error(request, '统一认证身份暂不可用，请重试或联系管理员。')
