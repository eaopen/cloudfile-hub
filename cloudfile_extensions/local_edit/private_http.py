"""Canonical HTTP/HTTPS CloudFile session transport.

The protocol is identical across both schemes. Django OIDC/CSRF and signed
device proofs are still mandatory, as are current ACL and native Branch CAS.
HTTP is plaintext and should only be deployed on trusted internal networks.
"""
from urllib.parse import urlsplit
from django.core.exceptions import DisallowedHost


def canonical_http(origin):
    if not isinstance(origin, str) or not 7 < len(origin) <= 255:
        return False
    if any(ord(c) < 33 or ord(c) > 126 for c in origin) or any(
            mark in origin for mark in ("%", "\\", "?", "#", "@", "*")):
        return False
    try:
        parsed = urlsplit(origin)
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname) and
                parsed.username is None and parsed.password is None and
                not parsed.path and not parsed.query and not parsed.fragment and
                parsed.netloc == parsed.netloc.lower() and
                not parsed.hostname.endswith(".") and
                (parsed.port is None or 1 <= parsed.port <= 65535) and
                origin == parsed.scheme + "://" + parsed.netloc)
    except ValueError:
        return False


def http_origin_allowed(origin):
    # Kept as a stable helper name for the native device-proof contract;
    # no per-host configuration is required for HTTP or HTTPS.
    return canonical_http(origin)


def transport_allowed(request):
    if request.is_secure():
        # Original HTTPS behavior, including testing proxies and ASGI.
        return True
    if request.scheme != "http":
        return False
    try:
        # Django get_host still enforces ALLOWED_HOSTS and reverse-proxy Host.
        return canonical_http(request.scheme + "://" + request.get_host())
    except (ValueError, RuntimeError, DisallowedHost):
        return False
