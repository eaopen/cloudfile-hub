"""Explicit OIDC initiation only; never install without the guarded callback."""
from uuid import uuid4
from urllib.parse import urlsplit

from django.http import HttpResponseRedirect, JsonResponse
from django.urls import path
from django.views import View

from ..common.errors import ContractError
from .resources import LoginResources
from .runtime import LoginRuntime


class LoginBeginView(View):
    resources = None
    return_path = "/"
    http_method_names = ["get"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "GET" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Login initiation only accepts GET", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure login is required", 401)
            if request.GET or request.read(1):
                raise ContractError("INVALID_REQUEST", "Login initiation takes no query or body", 400)
            if not isinstance(self.resources, LoginResources):
                raise ContractError("IDENTITY_UNAVAILABLE", "Login runtime is unavailable", 503)
            with self.resources.runtime(request_id) as runtime:
                if not isinstance(runtime, LoginRuntime):
                    raise RuntimeError("invalid login runtime assembly")
                response = HttpResponseRedirect("/")
                binding = runtime.browser.rotate(request, response)
                url = runtime.login.begin(binding, redirect=self.return_path)
                # Only the configured authorization endpoint may receive the
                # browser redirect; keep any upstream/config failure private.
                expected = urlsplit(self.resources.oidc.authorization_url)
                actual = urlsplit(url)
                if ((actual.scheme, actual.netloc, actual.path) !=
                        (expected.scheme, expected.netloc, expected.path)
                        or actual.fragment or actual.username or actual.password):
                    raise RuntimeError("invalid configured authorization redirect")
                response["Location"] = url
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("IDENTITY_UNAVAILABLE", "Login runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response


def login_begin_routes(*, resources, return_path="/"):
    """Trusted construction only, not automatic URL or capability registration."""
    if not isinstance(resources, LoginResources):
        raise ValueError("actual owned login resources required")
    if (not isinstance(return_path, str) or not return_path.startswith("/")
            or return_path.startswith("//") or "\\" in return_path
            or len(return_path) > 2048 or any(ord(char) < 32 for char in return_path)):
        raise ValueError("fixed local login return path required")
    return [path("begin/", LoginBeginView.as_view(resources=resources, return_path=return_path),
        name="cloudfile-oidc-begin")]
