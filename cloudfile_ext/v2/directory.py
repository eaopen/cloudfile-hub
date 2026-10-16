"""Exact-UID Directory subject source for the TTL projector.

One read of the trusted provider per refresh, addressed by the stable UID. The
snapshot is returned raw: ``Memberships.validate_subject`` remains the single
owner of subject validation, so the transport never decides what a valid
subject is and never substitutes cached or partial membership data when the
provider fails.
"""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .errors import IdentityUnavailable
from .identity import text


# 4096 memberships of 225 characters stay far below this ceiling.
MAXIMUM_RESPONSE = 1 << 22
DEFAULT_TIMEOUT = 5
MAXIMUM_TIMEOUT = 30


def trusted_url(value, *, insecure=False):
    """Accept only an administrator-configured absolute HTTPS origin."""
    try:
        url = urlsplit(value)
        if (url.hostname and url.scheme in ('https', 'http') and not url.username
                and not url.password and not url.query and not url.fragment
                and (url.scheme == 'https' or insecure)):
            return value.rstrip('/')
    except ValueError:
        pass
    raise IdentityUnavailable('CloudFile Directory URL must be a trusted HTTPS origin')


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        # Following a redirect would read the subject from an unconfigured origin.
        return None


class DirectorySubjectClient:
    """Callable ``fetch(uid)`` adapter for ``Memberships``; fails closed."""

    def __init__(self, base_url, token, *, timeout=DEFAULT_TIMEOUT, insecure=False, opener=None):
        self.base_url = trusted_url(text(base_url, 2048), insecure=insecure)
        self.token = text(token, 4096)
        if type(timeout) is not int or not 1 <= timeout <= MAXIMUM_TIMEOUT:
            raise ValueError('bounded Directory timeout required')
        self.timeout = timeout
        self.opener = opener if opener is not None else build_opener(_RejectRedirects())

    def __call__(self, uid):
        return self.fetch(uid)

    def fetch(self, uid):
        uid = text(uid)
        if uid in ('.', '..'):
            raise IdentityUnavailable('invalid Directory user id')
        request = Request(self.base_url + '/users/' + quote(uid, safe='') + '/context',
                          headers={'Authorization': 'Bearer ' + self.token,
                                   'Accept': 'application/json',
                                   'Cache-Control': 'no-store'})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if getattr(response, 'status', None) != 200:
                    raise IdentityUnavailable('Directory subject unavailable')
                body = response.read(MAXIMUM_RESPONSE + 1)
        except IdentityUnavailable:
            raise
        except HTTPError as error:
            # Absent, disabled, redirected and failed reads are all unproven subjects.
            raise IdentityUnavailable('Directory subject unavailable') from error
        except (URLError, OSError, ValueError) as error:
            raise IdentityUnavailable('Directory unreachable') from error
        if len(body) > MAXIMUM_RESPONSE:
            raise IdentityUnavailable('Directory response too large')
        try:
            value = json.loads(body.decode('utf-8'))
        except (UnicodeError, ValueError):
            raise IdentityUnavailable('invalid Directory response') from None
        if not isinstance(value, dict):
            raise IdentityUnavailable('invalid Directory response')
        return value
