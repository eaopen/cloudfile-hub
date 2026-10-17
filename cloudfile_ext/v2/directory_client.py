"""Short-lived machine JWT and bounded trusted Directory HTTP reads.

The same client is reusable for entity catalog reconciliation and the per-UID
subject TTL path. No cached or long-lived admin bearer is accepted.
"""
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt

from .errors import IdentityUnavailable
from .identity import text

_MAX_RESPONSE = 4 * 1024 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, url):
        return None


def configuration(settings):
    """Resolve administrator-owned settings; never use client-supplied URLs."""
    url = getattr(settings, 'CF_DIRECTORY_URL', None)
    kid = getattr(settings, 'CF_DIRECTORY_AUTH_KEY_ID', None)
    secret = getattr(settings, 'CF_DIRECTORY_AUTH_SECRET', None)
    if not all(isinstance(value, str) and value.strip() for value in (url, kid, secret)):
        raise IdentityUnavailable('trusted Directory connection is not configured')
    parsed = urlsplit(url)
    allow_http = getattr(settings, 'CF_DIRECTORY_ALLOW_HTTP', False) is True
    if (parsed.scheme not in ('https', 'http') or
            (parsed.scheme == 'http' and not allow_http) or
            not parsed.hostname or parsed.username or parsed.password or
            parsed.query or parsed.fragment or not parsed.path.startswith('/')):
        raise IdentityUnavailable('invalid trusted Directory origin')
    if len(secret.encode('utf-8')) < 32:
        raise IdentityUnavailable('invalid Directory service credential')
    timeout = getattr(settings, 'CF_DIRECTORY_TIMEOUT', 5)
    if type(timeout) is not int or not 1 <= timeout <= 30:
        raise IdentityUnavailable('invalid Directory service timeout')
    provider = getattr(settings, 'CF_DIRECTORY_PROVIDER', 'etech')
    return dict(url=text(url.rstrip('/'), 2048), kid=text(kid, 128),
                secret=secret, issuer=text(getattr(settings, 'CF_DIRECTORY_AUTH_ISSUER', 'cloudfile-sso'), 255),
                audience=text(getattr(settings, 'CF_DIRECTORY_AUTH_AUDIENCE', 'eap-directory'), 255),
                service=text(getattr(settings, 'CF_DIRECTORY_AUTH_SERVICE_ID', 'cloudfile'), 255),
                provider=text(provider, 32), timeout=timeout)


class DirectoryClient:
    def __init__(self, config, *, clock=time.time, opener=None):
        self.config, self.clock = config, clock
        self.opener = opener if opener is not None else build_opener(_NoRedirect())

    def _token(self):
        import uuid
        now = int(self.clock())
        claims = dict(iss=self.config['issuer'], aud=self.config['audience'],
                      sub=self.config['service'], scope='directory.read',
                      jti=uuid.uuid4().hex, iat=now, exp=now + 60)
        return jwt.encode(claims, self.config['secret'], algorithm='HS256',
                          headers={'kid': self.config['kid'], 'typ': 'JWT'})

    def _get(self, path):
        request = Request(self.config['url'] + path, headers={
            'Authorization': 'Bearer ' + self._token(),
            'Accept': 'application/json', 'Cache-Control': 'no-store'})
        try:
            with self.opener.open(request, timeout=self.config['timeout']) as reply:
                if getattr(reply, 'status', None) != 200:
                    raise IdentityUnavailable('Directory request unavailable')
                data = reply.read(_MAX_RESPONSE + 1)
        except (HTTPError, URLError, OSError, ValueError) as exc:
            raise IdentityUnavailable('Directory request unavailable') from exc
        if len(data) > _MAX_RESPONSE:
            raise IdentityUnavailable('Directory response exceeds limit')
        try:
            result = json.loads(data.decode('utf-8'))
        except (UnicodeError, ValueError):
            raise IdentityUnavailable('invalid Directory response') from None
        if not isinstance(result, dict):
            raise IdentityUnavailable('invalid Directory response')
        return result

    def entities(self):
        return self._get('/groups?view=entities')

    def subject(self, uid):
        uid = text(uid)
        if uid in ('.', '..'):
            raise IdentityUnavailable('invalid Directory subject ID')
        return self._get('/users/' + quote(uid, safe='') + '/context')
