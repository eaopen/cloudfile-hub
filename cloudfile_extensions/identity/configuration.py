"""Opt-in OIDC host wiring; no connections, authentication or readiness claim."""

from urllib.parse import urlsplit
import logging
import os

from django.core.exceptions import ImproperlyConfigured

from .oidc import OIDCConfig


logger = logging.getLogger(__name__)

LOGIN_PREFIX = "api/v2.1/cloudfile/extensions/identity/v1/"
SESSION_MIDDLEWARE = "django.contrib.sessions.middleware.SessionMiddleware"
GUARDED_MIDDLEWARE = "cloudfile_extensions.identity.session_middleware.CloudFileSessionMiddleware"
BACKEND = "cloudfile_extensions.identity.native_backend.CloudFileOIDCBackend"


def public_browser_scheme(settings, oidc):
    """Return 'http' or 'https' for the deployment's public CloudFile entry.

    Cookie security must follow the address real browsers use, never one login
    callback. Etech logs in over HTTP through the legacy Authentik OAuth entry,
    so inferring Secure from an HTTPS native OIDC callback would mark sessionid
    and csrftoken Secure and the browser would stop sending them -- every user
    logged out while the OIDC login itself was never used.

    ``CLOUDFILE_PUBLIC_URL`` declares the single public entry and wins. Without
    it every configured login redirect must agree; the legacy OAuth entry is
    preferred when they disagree because that is the entry existing users
    already have, and the mismatch is reported instead of silently flipping
    cookies. Both entries stay under the same SITE_ROOT, so one cookie path
    continues to serve both.
    """
    explicit = getattr(settings, "CLOUDFILE_PUBLIC_URL", None)
    if explicit is not None and explicit != "":
        if (not isinstance(explicit, str) or explicit != explicit.strip()
                or len(explicit) > 255):
            raise ValueError()
        parsed = urlsplit(explicit)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or parsed.netloc != parsed.netloc.lower()
                or any(ord(char) < 33 or ord(char) > 126 for char in explicit)
                or any(mark in explicit for mark in ("%", "\\"))):
            raise ValueError()
        return parsed.scheme
    oidc_scheme = urlsplit(oidc.redirect_uri).scheme
    oauth_scheme = None
    if getattr(settings, "ENABLE_OAUTH", False) is True:
        value = getattr(settings, "OAUTH_REDIRECT_URL", None)
        if isinstance(value, str) and value.strip():
            oauth_scheme = urlsplit(value).scheme
    if oauth_scheme not in ("http", "https"):
        oauth_scheme = None
    if oidc_scheme not in ("http", "https"):
        raise ValueError()
    if oauth_scheme is None or oauth_scheme == oidc_scheme:
        return oidc_scheme
    logger.warning("CloudFile: the legacy OAuth and native OIDC login entries use "
        "different schemes; cookie security follows the legacy OAuth entry. Declare "
        "CLOUDFILE_PUBLIC_URL to state one public entry explicitly.")
    return oauth_scheme


def configure_oidc_host(settings):
    enabled = getattr(settings, "CLOUDFILE_OIDC_ENABLED", False)
    backchannel = getattr(settings, "CLOUDFILE_OIDC_BACKCHANNEL_ENABLED", False)
    if type(backchannel) is not bool or (backchannel and enabled is not True):
        raise ImproperlyConfigured("OIDC backchannel requires explicit OIDC enablement and a boolean flag")
    if type(enabled) is not bool:
        raise ImproperlyConfigured("CLOUDFILE_OIDC_ENABLED must be a boolean")
    if not enabled:
        return
    # Validate everything before mutating the host settings. Never include the
    # configuration or the underlying exception (which may contain secrets).
    try:
        configured = getattr(settings, "CLOUDFILE_OIDC_CONFIG", None)
        oidc = OIDCConfig(**configured) if isinstance(configured, dict) else configured
        if not isinstance(oidc, OIDCConfig):
            raise ValueError()
        if getattr(settings, "CLOUDFILE_POLICY_CONFIG", None) is None:
            raise ValueError()
        if settings.SESSION_ENGINE != "django.contrib.sessions.backends.db":
            raise ValueError()
        if getattr(settings, "CLOUDFILE_OIDC_LOGIN_RESOURCES", None) is not None:
            raise ValueError()  # This host uses the post-fork ownership mode only.
        jit = getattr(settings, "CLOUDFILE_OIDC_JIT_ENABLED", False)
        if type(jit) is not bool:
            raise ValueError()
        if (not isinstance(settings.MIDDLEWARE, (list, tuple))
                or not isinstance(settings.AUTHENTICATION_BACKENDS, (list, tuple))):
            raise ValueError()
        middleware = list(settings.MIDDLEWARE)
        entries = [entry for entry in middleware if entry in (SESSION_MIDDLEWARE, GUARDED_MIDDLEWARE)]
        if len(entries) != 1:
            raise ValueError()
        backends = tuple(settings.AUTHENTICATION_BACKENDS)
        site_root = getattr(settings, "SITE_ROOT", "/")
        if (not isinstance(site_root, str) or not site_root.startswith("/")
                or not site_root.endswith("/") or "//" in site_root or "\\" in site_root):
            raise ValueError()
        callback = urlsplit(oidc.redirect_uri)
        if callback.path != site_root + LOGIN_PREFIX + "callback/" or callback.query or callback.fragment:
            raise ValueError()
        if oidc.post_logout_redirect_uri is not None:
            logout = urlsplit(oidc.post_logout_redirect_uri)
            if logout.path != site_root + LOGIN_PREFIX + "logout/return/" or logout.query or logout.fragment:
                raise ValueError()
        return_path = getattr(settings, "CLOUDFILE_OIDC_RETURN_PATH", site_root)
        from .hosted_routes import hosted_login_routes
        from ..authorization.gunicorn import login_resources_scope
        hosted_login_routes(resources_scope=login_resources_scope, return_path=return_path,
            backchannel_enabled=backchannel,
            read_tickets_enabled=getattr(settings, "CLOUDFILE_TRANSFER_ENABLED", False))
        existing_scope = getattr(settings, "CLOUDFILE_OIDC_LOGIN_RESOURCE_SCOPE", None)
        if existing_scope is not None and existing_scope is not login_resources_scope:
            raise ValueError()
        # Resolve the browser cookie scheme here, before any mutation, so an
        # ambiguous public entry fails the whole host instead of half-applying.
        public_secure = public_browser_scheme(settings, oidc) == "https"
    except Exception:
        raise ImproperlyConfigured("CloudFile OIDC host requires valid OIDC/policy configuration, "
            "fixed callback paths, database sessions and one session middleware; "
            "alternative login resource ownership must be disabled") from None
    settings.CLOUDFILE_OIDC_CONFIG = oidc
    settings.CLOUDFILE_OIDC_LOGIN_RESOURCE_SCOPE = login_resources_scope
    settings.CLOUDFILE_OIDC_RETURN_PATH = return_path
    # Preserve the established login entry when OAuth is enabled. Native OIDC
    # always has its own route and never replaces the legacy callback.
    if not getattr(settings, "ENABLE_OAUTH", False):
        settings.LOGIN_URL = site_root + LOGIN_PREFIX + "begin/"
    settings.MIDDLEWARE = [GUARDED_MIDDLEWARE if entry == SESSION_MIDDLEWARE else entry
                           for entry in middleware]
    settings.AUTHENTICATION_BACKENDS = backends if BACKEND in backends else backends + (BACKEND,)
    # Browser cookies follow the deployment's public CloudFile entry, not the
    # OIDC callback scheme: an HTTPS callback on an HTTP deployment would mark
    # the legacy OAuth session Secure and the browser would stop sending it.
    # HttpOnly, SameSite and CSRF stay at their Django defaults; both login
    # entries live under SITE_ROOT, so one cookie path still serves both.
    if not public_secure or any(urlsplit(value).scheme == "http" for value in (
            oidc.redirect_uri, oidc.issuer, oidc.authorization_url,
            oidc.token_url, oidc.userinfo_url, oidc.jwks_url)):
        # oauthlib refuses HTTP authorization even when the deployment's
        # fixed public entry or IdP URL is explicitly HTTP; this is required
        # for HTTP-mode deployments. It is independent of cookie security. No
        # redirect endpoint is taken from requests.
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    settings.SESSION_COOKIE_SECURE = public_secure
    settings.SESSION_COOKIE_HTTPONLY = True
    settings.CSRF_COOKIE_SECURE = public_secure
