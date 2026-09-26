"""Explicit guarded OIDC callback; no automatic URL/capability registration."""
import re
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.views import View

from ..common.errors import ContractError
from .browser_binding import BINDING_COOKIE
from .login import PendingLogin
from .native_session import NativeOIDCSession
from .resources import LoginResources


class LoginCallbackView(View):
    resources = None
    http_method_names = ["get"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        created_session = False
        try:
            if request.method != "GET" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "OIDC callback only accepts GET", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure callback is required", 401)
            if request.read(1) or request.headers.get("Authorization"):
                raise ContractError("INVALID_REQUEST", "Callback takes no body or authorization header", 400)
            if set(request.GET) != {"state", "code"} or any(len(request.GET.getlist(key)) != 1 for key in request.GET):
                raise ContractError("INVALID_REQUEST", "Callback requires exact state and code", 400)
            state, code = request.GET["state"], request.GET["code"]
            if (not re.fullmatch(r"[A-Za-z0-9_-]{43}", state) or not code or len(code) > 4096
                    or any(ord(char) < 32 for char in code)):
                raise ContractError("INVALID_REQUEST", "Invalid callback parameters", 400)
            raw_cookie = request.headers.get("Cookie", "")
            bindings = [part.strip().split("=", 1)[1] for part in raw_cookie.split(";")
                if "=" in part and part.strip().split("=", 1)[0] == BINDING_COOKIE]
            if (len(raw_cookie) > 8192 or len(bindings) != 1
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", bindings[0])
                    or request.COOKIES.get(BINDING_COOKIE) != bindings[0]):
                raise ContractError("AUTHENTICATION_REQUIRED", "Exact browser login binding required", 401)
            if not isinstance(self.resources, LoginResources):
                raise ContractError("IDENTITY_UNAVAILABLE", "Login runtime is unavailable", 503)
            with self.resources.runtime(request_id) as runtime:
                value = NativeOIDCSession().complete(request, runtime,
                    state=state, code=code, binding=bindings[0])
                if isinstance(value, PendingLogin):
                    if (not isinstance(value.status_token, str)
                            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value.status_token)):
                        raise RuntimeError("pending browser proof unavailable")
                    response = JsonResponse(dict(job_id=value.job_id, status="pending",
                        status_token=value.status_token), status=202)
                else:
                    response = value
                    created_session = True
        except Exception as error:
            if created_session:
                # Resource shutdown can fail after finalization returned. Do
                # not return a successful session when owned cleanup failed.
                from seahub.auth.models import AnonymousUser
                request.user = AnonymousUser()
                try:
                    request.session.flush()
                except Exception:
                    error = ContractError("IDENTITY_UNAVAILABLE", "Session cleanup is unavailable", 503)
            if not isinstance(error, ContractError):
                error = ContractError("IDENTITY_UNAVAILABLE", "Login runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=error.status)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response


def login_callback_routes(*, resources):
    if not isinstance(resources, LoginResources):
        raise ValueError("actual owned login resources required")
    return [path("callback/", LoginCallbackView.as_view(resources=resources),
        name="cloudfile-oidc-callback")]
