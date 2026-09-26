"""Explicit replacement for Django SessionMiddleware on an OIDC-enabled host.

Guards request entry and native session persistence, not file effect authority.
Streaming OIDC responses remain unavailable until their release guard exists.
"""
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import JsonResponse

from ..common.errors import ContractError
from .resources import LoginResources
from .native_session import BACKEND
from .session_authority import OIDCSessionAuthority


class CloudFileSessionMiddleware(SessionMiddleware):
    def __init__(self, get_response):
        super().__init__(get_response)
        resources = getattr(settings, "CLOUDFILE_OIDC_LOGIN_RESOURCES", None)
        if not isinstance(resources, LoginResources):
            raise ImproperlyConfigured("CloudFile session middleware requires actual login resources")
        if settings.SESSION_ENGINE != "django.contrib.sessions.backends.db":
            raise ImproperlyConfigured("CloudFile guarded sessions require the database backend")
        self.authority = OIDCSessionAuthority(resources)

    @staticmethod
    def oidc(request):
        from seahub.auth import BACKEND_SESSION_KEY
        return request.session.get(BACKEND_SESSION_KEY) == BACKEND

    def failure(self, request, error):
        from seahub.auth.models import AnonymousUser
        request.user = request._cached_user = AnonymousUser()
        if error.status == 401:
            try:
                request.session.flush()
            except Exception:
                error = ContractError("IDENTITY_UNAVAILABLE", "Session cleanup is unavailable", 503)
        response = JsonResponse(error.response(str(uuid4())), status=error.status)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Referrer-Policy"] = "no-referrer"
        # Never save a stale in-memory authenticated session after failure.
        if error.status >= 500:
            return response
        return super().process_response(request, response)

    def process_request(self, request):
        super().process_request(request)
        try:
            if self.oidc(request):
                self.authority.check(request)
        except ContractError as error:
            return self.failure(request, error)
        except Exception:
            return self.failure(request, ContractError("IDENTITY_UNAVAILABLE", "Session authority is unavailable", 503))

    def process_response(self, request, response):
        try:
            if not self.oidc(request):
                return super().process_response(request, response)
            if response.streaming:
                raise ContractError("IDENTITY_UNAVAILABLE", "Guarded streaming response is unavailable", 503)
            # Enclose the actual Django save, not just a pre-save check. Logout
            # intake/deletion uses this same provider lock, so a stale request
            # cannot save its session after notification acceptance.
            with self.authority.guard(request):
                return super().process_response(request, response)
        except ContractError as error:
            response.close()
            return self.failure(request, error)
        except Exception:
            response.close()
            return self.failure(request, ContractError("IDENTITY_UNAVAILABLE", "Session authority is unavailable", 503))
