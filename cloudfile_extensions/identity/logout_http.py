"""CSRF-protected local CE logout, not IdP/session-wide single logout."""
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.views import View

from ..common.errors import ContractError
from .browser_binding import BINDING_COOKIE, BrowserLoginBindings, request_binding
from .resources import LoginResources
from .session_authority import OIDCSessionAuthority


class LocalLogoutView(View):
    resources = None
    http_method_names = ["post"]

    def logout_response(self, request):
        return JsonResponse(dict(local_logged_out=True, idp_logged_out=False))

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        termination_started = False
        binding = None
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Local logout only accepts POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure logout is required", 401)
            if request.GET or request.read(1) or request.headers.get("Authorization"):
                raise ContractError("INVALID_REQUEST", "Local logout takes no query, body or authorization header", 400)
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            if not isinstance(self.resources, LoginResources):
                raise ContractError("IDENTITY_UNAVAILABLE", "Logout runtime is unavailable", 503)
            raw = request.headers.get("Cookie", "")
            if any(part.strip().split("=", 1)[0] == BINDING_COOKIE for part in raw.split(";")):
                binding = request_binding(request)
            # Prepare protocol response while the server hint is still present;
            # it is never returned if native or browser cleanup then fails.
            response = self.logout_response(request)
            from seahub.auth import logout
            from seahub.auth.models import AnonymousUser
            def terminate_native(native_request):
                try:
                    logout(native_request)  # native session and remembered repo passwords
                except Exception:
                    native_request.user = AnonymousUser()
                    native_request.session.flush()
                    raise ContractError("IDENTITY_UNAVAILABLE", "Native logout cleanup is unavailable", 503) from None
            termination_started = True
            OIDCSessionAuthority(self.resources).terminate(request, terminate_native)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("IDENTITY_UNAVAILABLE", "Logout runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        if termination_started:
            # SQL/native cleanup errors must not skip the independent browser
            # registry. Replace an RP redirect/form with a safe failure if any
            # cleanup fails, and attach cookie expiry to that final response.
            try:
                if binding is not None:
                    BrowserLoginBindings(self.resources.resources.redis,
                        prefix=self.resources.prefix + "oidc:browser:").clear(binding, response)
            except Exception:
                error = ContractError("IDP_STATE_UNAVAILABLE", "Browser login cleanup is unavailable", 503)
                response = JsonResponse(error.response(request_id), status=503)
            response.set_cookie(BINDING_COOKIE, "", max_age=0, path="/",
                secure=True, httponly=True, samesite="Lax")
            response.delete_cookie("seahub_auth")
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response
