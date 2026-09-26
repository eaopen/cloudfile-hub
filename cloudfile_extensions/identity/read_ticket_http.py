"""Explicitly unregistered OIDC ticket HTTP adapter and owned service scope."""
from contextlib import contextmanager
from uuid import uuid4

from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..authorization.runtime import AuthenticatedPolicyActor
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from .read_ticket import OIDCReadTicketIssuer
from .resources import LoginResources
from .session_authority import OIDCSessionAuthority


class OIDCReadTicketFactory:
    def __init__(self, resources, *, authenticate):
        if not isinstance(resources, LoginResources) or not callable(authenticate):
            raise ValueError("actual login resources and trusted host authenticator required")
        self.resources, self.authenticate = resources, authenticate

    @contextmanager
    def __call__(self, request, request_id):
        actor = self.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Authenticated download identity is required", 401)
        authority = OIDCSessionAuthority(self.resources)
        authority.check(request)  # Before directory allocation or external I/O.
        with self.resources.resources.preparation(actor.user_id, request_id) as preparation:
            if preparation.state.username(actor.user_id) != actor.native_username:
                raise ContractError("ACCESS_DENIED", "Download identity does not match", 403)
            yield OIDCReadTicketIssuer(preparation, authority)


class OIDCReadTicketView(DirectoryPolicyView):
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != "POST" or args or kwargs:
                raise ContractError("METHOD_NOT_ALLOWED", "Download tickets require POST", 405)
            if not request.is_secure():
                raise ContractError("AUTHENTICATION_REQUIRED", "Secure session is required", 401)
            if request.GET or request.headers.get("Authorization") or request.headers.get("Content-Encoding"):
                raise invalid("Download tickets accept only native session JSON")
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError("ACCESS_DENIED", "CSRF verification failed", 403)
            body = self._body(request)  # Bounded UTF-8 JSON, rejects duplicate fields.
            object_fields(body, ("reference",), ("operation",))
            if not isinstance(self.service_factory, OIDCReadTicketFactory):
                raise ContractError("POLICY_UNAVAILABLE", "Download ticket runtime is unavailable", 503)
            with self.service_factory(request, request_id) as issuer:
                result = issuer.issue(request, body["reference"],
                    operation=body.get("operation", "download"))
            response = JsonResponse(result, status=201)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError("POLICY_UNAVAILABLE", "Download ticket runtime is unavailable", 503)
            response = JsonResponse(error.response(request_id), status=503)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["Vary"] = "Cookie"
        response["X-Request-ID"] = request_id
        return response
