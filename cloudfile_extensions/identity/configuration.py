"""Opt-in OIDC host wiring; no connections, authentication or readiness claim."""

from urllib.parse import urlsplit
import os

from django.core.exceptions import ImproperlyConfigured

from .oidc import OIDCConfig


LOGIN_PREFIX = "api/v2.1/cloudfile/extensions/identity/v1/"
SESSION_MIDDLEWARE = "django.contrib.sessions.middleware.SessionMiddleware"
GUARDED_MIDDLEWARE = "cloudfile_extensions.identity.session_middleware.CloudFileSessionMiddleware"
BACKEND = "cloudfile_extensions.identity.native_backend.CloudFileOIDCBackend"


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
    # Browser cookies follow the actual application scheme. On internal
    # HTTP, Secure would make the browser discard the session entirely.
    callback_secure = urlsplit(oidc.redirect_uri).scheme == "https"
    if not callback_secure or any(urlsplit(value).scheme == "http" for value in (
            oidc.issuer, oidc.authorization_url, oidc.token_url,
            oidc.userinfo_url, oidc.jwks_url)):
        # oauthlib refuses HTTP authorization even when the deployment's
        # fixed callback/IdP URL is explicitly HTTP; this is required for
        # native HTTP-mode OIDC. No redirect endpoint is taken from requests.
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    settings.SESSION_COOKIE_SECURE = callback_secure
    settings.SESSION_COOKIE_HTTPONLY = True
    settings.CSRF_COOKIE_SECURE = callback_secure
