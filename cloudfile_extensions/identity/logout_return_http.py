"""Browser-bound RP return diagnostic; never logs out a newly created session."""
import re
from uuid import uuid4
from urllib.parse import urlsplit

from django.http import JsonResponse
from django.views import View

from ..common.errors import ContractError
from .logout_state import LogoutStates, LOGOUT_COOKIE
from .resources import LoginResources


class LogoutReturnView(View):
    resources = None
    http_method_names = ["get"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "GET" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Logout return only accepts GET", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure logout return required", 401)
            if request.read(1) or request.headers.get("Authorization"):
                raise ContractError("INVALID_REQUEST", "Logout return takes no body or authorization header", 400)
            if set(request.GET) != {"state"} or len(request.GET.getlist("state")) != 1:
                raise ContractError("INVALID_REQUEST", "Exact logout return state required", 400)
            if not isinstance(self.resources, LoginResources):
                raise ContractError("IDENTITY_UNAVAILABLE", "Logout return runtime is unavailable", 503)
            config = self.resources.oidc
            if config.post_logout_redirect_uri is None:
                raise ContractError("IDENTITY_UNAVAILABLE", "Logout return is not configured", 503)
            actual, expected = urlsplit(request.build_absolute_uri()), urlsplit(config.post_logout_redirect_uri)
            if (actual.scheme, actual.netloc, actual.path) != (expected.scheme, expected.netloc, expected.path):
                raise ContractError("INVALID_REQUEST", "Logout return address does not match deployment", 400)
            raw = request.headers.get("Cookie", "")
            if len(raw) > 8192:
                raise ContractError("AUTHENTICATION_REQUIRED", "Invalid logout binding cookie", 401)
            cookies = [part.strip().split("=", 1)[1] for part in raw.split(";")
                if "=" in part and part.strip().split("=", 1)[0] == LOGOUT_COOKIE]
            if (len(cookies) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", cookies[0])
                    or request.COOKIES.get(LOGOUT_COOKIE) != cookies[0]):
                raise ContractError("AUTHENTICATION_REQUIRED", "Exact logout browser binding required", 401)
            LogoutStates(self.resources.resources.redis, issuer=config.issuer,
                client_id=config.client_id, prefix=self.resources.prefix + "oidc:logout:").consume(
                    request.GET["state"], cookies[0])
            # A delayed return must not destroy an intervening fresh login.
            # State proves correlation, not that every IdP/RP session ended.
            response = JsonResponse(dict(rp_returned=True, idp_logged_out=None))
            response.set_cookie(LOGOUT_COOKIE, "", max_age=0, path="/",
                secure=True, httponly=True, samesite="Lax")
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("IDENTITY_UNAVAILABLE", "Logout return runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response
