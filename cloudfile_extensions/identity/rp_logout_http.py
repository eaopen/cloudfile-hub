"""Fixed-endpoint RP logout POST form; not confirmation of global IdP logout."""
import secrets
from urllib.parse import urlsplit

from django.conf import settings
from django.http import HttpResponse
from django.utils.html import format_html

from ..common.errors import ContractError
from .logout_http import LocalLogoutView
from .native_session import BACKEND, LOGOUT_HINT_KEY, SERVER_SESSION_ENGINES


class RPLogoutView(LocalLogoutView):
    def logout_response(self, request):
        from seahub.auth import BACKEND_SESSION_KEY
        config = self.resources.oidc
        if config.end_session_url is None:
            raise ContractError("IDENTITY_UNAVAILABLE", "RP logout is not configured", 503)
        if (settings.SESSION_ENGINE not in SERVER_SESSION_ENGINES
                or request.session.get(BACKEND_SESSION_KEY) != BACKEND
                or not getattr(request.user, "is_authenticated", False)):
            raise ContractError("AUTHENTICATION_REQUIRED", "Current OIDC server session required", 401)
        hint = request.session.get(LOGOUT_HINT_KEY)
        if (not isinstance(hint, dict) or set(hint) != {"issuer", "client_id", "id_token"}
                or hint["issuer"] != config.issuer or hint["client_id"] != config.client_id
                or not isinstance(hint["id_token"], str) or not 1 <= len(hint["id_token"]) <= 32768):
            raise ContractError("IDENTITY_UNAVAILABLE", "Verified RP logout hint is unavailable", 503)
        # HTML is a protocol POST carrier, not a customization UI. No token
        # appears in Location/query; CSP permits only this fixed IdP origin.
        nonce = secrets.token_urlsafe(24)
        html = format_html('<!doctype html><html><head><meta charset="utf-8">'
            '<title>Sign out</title></head><body><form id="rp-logout" method="post" action="{}">'
            '<input type="hidden" name="id_token_hint" value="{}">'
            '<input type="hidden" name="post_logout_redirect_uri" value="{}">'
            '<button type="submit">Continue sign out</button></form>'
            '<script nonce="{}">document.getElementById("rp-logout").submit();</script></body></html>',
            config.end_session_url, hint["id_token"], config.post_logout_redirect_uri, nonce)
        response = HttpResponse(html, content_type="text/html; charset=utf-8")
        endpoint = urlsplit(config.end_session_url)
        origin = endpoint.scheme + "://" + endpoint.netloc
        response["Content-Security-Policy"] = ("default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action " + origin + "; script-src 'nonce-" + nonce + "'")
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        return response
