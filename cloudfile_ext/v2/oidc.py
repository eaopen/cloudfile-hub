"""Strict OIDC identity proof before entering the native OAuth account/session path."""
import base64
from functools import lru_cache
import hashlib
import secrets
from urllib.parse import urlsplit

import jwt

from .errors import IdentityUnavailable


@lru_cache(maxsize=8)
def key_client(uri):
    # URI comes only from administrator configuration, never from token headers.
    return jwt.PyJWKClient(uri, timeout=5)


def configuration(settings):
    issuer = getattr(settings, 'OAUTH_OIDC_ISSUER', '')
    jwks_uri = getattr(settings, 'OAUTH_OIDC_JWKS_URI', '')
    for value in (issuer, jwks_uri):
        url = urlsplit(value)
        if (not url.hostname or url.scheme not in ('https', 'http') or
                url.username or url.password or url.query or url.fragment or
                (url.scheme == 'http' and not getattr(settings, 'OAUTH_ENABLE_INSECURE_TRANSPORT', False))):
            raise IdentityUnavailable('OIDC issuer and JWKS configuration required')
    return issuer, jwks_uri


def verify_id_token(token, *, issuer, client_id, nonce, jwks_uri):
    try:
        raw = token['id_token']
        if not isinstance(raw, str) or not raw or not isinstance(nonce, str) or not nonce:
            raise ValueError()
        key = key_client(jwks_uri).get_signing_key_from_jwt(raw).key
        claims = jwt.decode(raw, key, algorithms=['RS256'], issuer=issuer, audience=client_id,
                            options={'require': ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce']})
        if (not isinstance(claims['sub'], str) or not claims['sub'] or
                not isinstance(claims['nonce'], str) or
                not secrets.compare_digest(claims['nonce'], nonce)):
            raise ValueError()
        audience = claims['aud']
        if ((isinstance(audience, list) and len(audience) > 1 and claims.get('azp') != client_id) or
                ('azp' in claims and claims['azp'] != client_id)):
            raise ValueError()
        if 'at_hash' in claims:
            digest = hashlib.sha256(token['access_token'].encode('ascii')).digest()
            expected = base64.urlsafe_b64encode(digest[:len(digest) // 2]).rstrip(b'=').decode()
            if not isinstance(claims['at_hash'], str) or not secrets.compare_digest(claims['at_hash'], expected):
                raise ValueError()
        return claims
    except (jwt.PyJWTError, KeyError, TypeError, ValueError, UnicodeError) as error:
        raise IdentityUnavailable('OIDC identity proof rejected') from error


def verified_oidc_subject(claims, user_info):
    """Bind only the signed OIDC subject, never a UserInfo email or display name.

    A deployments's optional business UID must agree in both the ID Token
    and UserInfo before a Directory-aware JIT may reuse that UID.
    """
    if (not isinstance(claims, dict) or not isinstance(user_info, dict)
            or not isinstance(claims.get('sub'), str) or not claims['sub']
            or claims['sub'] != user_info.get('sub')):
        raise IdentityUnavailable('OIDC subject mismatch')
    if 'userId' in claims and (not isinstance(claims['userId'], str)
                               or not claims['userId']
                               or claims['userId'] != user_info.get('userId')):
        raise IdentityUnavailable('OIDC user identity mismatch')
    return claims['sub']


def oidc_login(request):
    # Reuse the configured confidential OAuth code flow and the same callback,
    # account binding, Session, CSRF and downstream authorization.
    from seahub.oauth.views import oauth_login
    request._cloudfile_oidc = True
    return oauth_login(request)
