"""Explicit OIDC route assembly with per-request post-fork resource ownership."""
from contextlib import contextmanager
from uuid import uuid4

from django.http import JsonResponse
from django.urls import path
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from ..common.errors import ContractError
from .begin_http import LoginBeginView, login_begin_routes
from .callback_http import LoginCallbackView
from .logout_http import LocalLogoutView
from .logout_return_http import LogoutReturnView
from .pending_http import PendingStatusView
from .resources import LoginResources
from .rp_logout_http import RPLogoutView
from .logout_backchannel_http import BackchannelLogoutView
from .logout_resources import LogoutResources
from .read_ticket_http import OIDCReadTicketFactory, OIDCReadTicketView
from .manual_update_http import OIDCManualUpdateView


class HostedLoginView(View):
    resources_scope = None
    operation = None
    return_path = "/"

    def dispatch(self, request, *args, **kwargs):
        try:
            if not callable(self.resources_scope):
                raise ContractError("IDENTITY_UNAVAILABLE", "Login worker is unavailable", 503)
            # Resolve only at request time. URLConf may be loaded by a preload
            # master; it must not retain that parent's SQL/Redis/host locks.
            with self.resources_scope() as resources:
                if not isinstance(resources, LoginResources):
                    raise ContractError("IDENTITY_UNAVAILABLE", "Login resources are unavailable", 503)
                views = {"begin": LoginBeginView, "callback": LoginCallbackView,
                    "logout": LocalLogoutView, "idp": RPLogoutView, "return": LogoutReturnView}
                if self.operation == "backchannel":
                    adapter = BackchannelLogoutView.as_view(resources=LogoutResources(resources, enabled=True))
                elif self.operation == "read":
                    adapter = OIDCReadTicketView.as_view(service_factory=OIDCReadTicketFactory(resources))
                elif self.operation == "update":
                    adapter = OIDCManualUpdateView.as_view(resources=resources)
                elif self.operation == "pending":
                    @contextmanager
                    def pending(request_id):
                        with resources.runtime(request_id) as runtime:
                            yield runtime.pending
                    adapter = PendingStatusView.as_view(service_factory=pending)
                else:
                    view = views.get(self.operation)
                    if view is None:
                        raise ContractError("IDENTITY_UNAVAILABLE", "Login route is unavailable", 503)
                    options = dict(resources=resources)
                    if self.operation == "begin":
                        # Reuse the exact fixed-local-return validation contract.
                        login_begin_routes(resources=resources, return_path=self.return_path)
                        options["return_path"] = self.return_path
                    adapter = view.as_view(**options)
                return adapter(request, *args, **kwargs)
        except Exception as error:
            if not isinstance(error, ContractError):
                error = ContractError("IDENTITY_UNAVAILABLE", "Login worker is unavailable", 503)
            request_id = str(uuid4())
            response = JsonResponse(error.response(request_id), status=error.status)
            response["Cache-Control"] = "no-store, max-age=0"
            response["Pragma"] = "no-cache"
            response["Referrer-Policy"] = "no-referrer"
            response["Vary"] = "Cookie, Authorization"
            response["X-Request-ID"] = request_id
            return response


def hosted_login_routes(*, resources_scope, return_path="/", backchannel_enabled=False,
                        read_tickets_enabled=False):
    """Configuration only; never enable capabilities, backends or middleware."""
    if not callable(resources_scope):
        raise ValueError("trusted process-owned login scope required")
    if type(backchannel_enabled) is not bool:
        raise ValueError("explicit boolean backchannel enablement required")
    if type(read_tickets_enabled) is not bool:
        raise ValueError("explicit boolean read ticket enablement required")
    if (not isinstance(return_path, str) or not return_path.startswith("/") or
            return_path.startswith("//") or "\\" in return_path or len(return_path) > 2048 or
            any(ord(char) < 32 for char in return_path)):
        raise ValueError("fixed local login return path required")
    routes = (("begin/", "begin", "cloudfile-oidc-begin"),
        ("callback/", "callback", "cloudfile-oidc-callback"),
        ("pending/", "pending", "cloudfile-oidc-pending"),
        ("logout/", "logout", "cloudfile-oidc-local-logout"),
        ("logout/idp/", "idp", "cloudfile-oidc-rp-logout"),
        ("logout/return/", "return", "cloudfile-oidc-logout-return"))
    result = [path(route, HostedLoginView.as_view(resources_scope=resources_scope,
        operation=operation, return_path=return_path), name=name) for route, operation, name in routes]
    if read_tickets_enabled:
        result.append(path("read-tickets/", HostedLoginView.as_view(
            resources_scope=resources_scope, operation="read"), name="cloudfile-oidc-read-ticket"))
        result.append(path("manual-update/", HostedLoginView.as_view(
            resources_scope=resources_scope, operation="update"), name="cloudfile-oidc-manual-update"))
    if backchannel_enabled:
        # CSRF middleware sees the outer hosted view. Only this cookie-free,
        # signed server notification gets an exemption, never browser logout.
        result.append(path("logout/backchannel/", csrf_exempt(HostedLoginView.as_view(
            resources_scope=resources_scope, operation="backchannel")),
            name="cloudfile-oidc-backchannel-logout"))
    return result
