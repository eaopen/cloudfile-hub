# -*- coding: utf-8 -*-
"""Outbound calls to a customer's own service.

Several planned capabilities need to ask something outside CloudFile: pull
directory ACL rules from an existing permission system, forward an audit
record to a SIEM, hand a search query to a company-wide index. They all need
the same unglamorous parts -- timeout, authentication, retry, and a decision
about what to do when the far end is down -- so those live here once rather
than three times.

One rule this module exists to enforce:

    **An external service is never on the synchronous permission path.**

It is tempting to resolve a directory ACL by calling the customer's system per
check. Do not. check_folder_permission is called 255 times across Seahub, and
seaf-server calls its own equivalent on every RPC; a network round trip in
there turns one slow HTTP endpoint into a server-wide stall, and it would push
an HTTP client into the C enforcement path, which has no business making
network calls. External rules reach CloudFile the other way round: a periodic
task pulls them (or the far end pushes them to a webhook) into the cf_* tables,
and enforcement reads those tables exactly as it does for locally configured
rules. See docs/EXTENSION-POINTS.md.

So the calls made through this module are all off the request path, which is
why the defaults here favour "give up and log" over "retry hard".
"""

import json
import logging
import time
import urllib.error
import urllib.request

from django.conf import settings

logger = logging.getLogger(__name__)

#: What to do when the far end cannot be reached.
FAIL_CLOSED = 'closed'   # propagate the error; the caller must not proceed
FAIL_OPEN = 'open'       # log and return None; the caller carries on

DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 2


class ExternalServiceError(Exception):
    """The far end failed and the caller asked to fail closed."""


class ExternalService(object):
    """A configured HTTP endpoint belonging to the deployment's operator.

    Authentication follows the convention Seahub already uses for its own
    internal services: a short-lived HS256 JWT signed with a shared secret,
    sent as ``Authorization: Token <jwt>``. Reusing it means an operator who
    has already wired up seafevents has nothing new to learn, and we are not
    inventing a second signing scheme for the same job.
    """

    def __init__(self, name, url, secret='', timeout=DEFAULT_TIMEOUT,
                 retries=DEFAULT_RETRIES, on_failure=FAIL_CLOSED):
        self.name = name
        self.url = url.rstrip('/')
        self.secret = secret
        self.timeout = timeout
        self.retries = retries
        self.on_failure = on_failure

    # -- construction ------------------------------------------------------

    @classmethod
    def from_settings(cls, name, on_failure=FAIL_CLOSED):
        """Build from ``CF_SERVICE_<NAME>_*`` settings, or None if unset.

        Returning None rather than raising lets a capability be enabled
        without an external service configured -- the local provider is
        usually the default, and the external one is opt-in.
        """
        prefix = 'CF_SERVICE_%s_' % name.upper().replace('-', '_')
        url = getattr(settings, prefix + 'URL', '')
        if not url:
            return None
        return cls(
            name=name,
            url=url,
            secret=getattr(settings, prefix + 'SECRET', ''),
            timeout=getattr(settings, prefix + 'TIMEOUT', DEFAULT_TIMEOUT),
            retries=getattr(settings, prefix + 'RETRIES', DEFAULT_RETRIES),
            on_failure=getattr(settings, prefix + 'ON_FAILURE', on_failure),
        )

    # -- calling -----------------------------------------------------------

    def _headers(self):
        headers = {'Content-Type': 'application/json'}
        if not self.secret:
            return headers
        try:
            import jwt
        except ImportError:                      # pragma: no cover
            logger.error('PyJWT missing; calling %s unauthenticated',
                         self.name)
            return headers
        # iss/aud bind the token to one purpose: a caller that holds the
        # secret cannot reuse it against an unrelated endpoint on the far
        # side (decision 2026-08-28 §8.1). The receiver verifies the same
        # fixed pair -- one line each, both ends in the compose .env.
        now = int(time.time())
        token = jwt.encode(
            {'exp': now + 300,
             'iss': 'cloudfile-sso',
             'aud': 'eap-directory'},
            self.secret, algorithm='HS256')
        headers['Authorization'] = 'Token %s' % token
        return headers

    def call(self, path, payload=None, method='POST'):
        """Call `path`, returning the decoded JSON body.

        Returns None when the call failed and this service fails open. Raises
        ExternalServiceError when it fails closed.
        """
        url = '%s/%s' % (self.url, path.lstrip('/'))
        body = json.dumps(payload).encode('utf-8') if payload is not None else None

        last = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=body, method=method,
                                         headers=self._headers())
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode('utf-8')
                return json.loads(raw) if raw else {}
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last = exc
                # A 4xx means we are asking wrongly; retrying cannot help and
                # only multiplies the log noise.
                code = getattr(exc, 'code', None)
                if code is not None and 400 <= code < 500:
                    break
                if attempt < self.retries:
                    time.sleep(2 ** attempt)

        if self.on_failure == FAIL_OPEN:
            logger.warning('external service %s failed (open): %s',
                           self.name, last)
            return None
        raise ExternalServiceError('%s: %s' % (self.name, last))
