"""Explicitly unregistered OIDC ticket HTTP adapter and owned service scope."""
from contextlib import contextmanager
from uuid import uuid4

from django.http import JsonResponse
from django.conf import settings
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization.http import DirectoryPolicyView
from ..authorization.core import PolicyCore
from ..authorization.read import ContentReadAuthority
from ..authorization.runtime import AuthenticatedPolicyActor
from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import resource_ref
from .read_ticket import OIDCReadTicketIssuer
from .resources import LoginResources
from .session_authority import OIDCSessionAuthority
from .native_backend import CloudFileOIDCBackend
from .native_session import BACKEND
from .transfer_audit import record_transfer, audit_peer_ip


def native_download_actor(request):
    """Fixed OIDC session/backend and bidirectional native Profile binding."""
    from seahub.auth import BACKEND_SESSION_KEY, SESSION_KEY
    from seahub.base.accounts import User
    from seahub.profile.models import Profile
    from django.core.exceptions import MultipleObjectsReturned
    user = getattr(request, "user", None)
    session = getattr(request, "session", None)
    if (not request.is_secure() or session is None
            or session.get(BACKEND_SESSION_KEY) != BACKEND
            or not isinstance(user, User) or user.is_authenticated is not True
            or session.get(SESSION_KEY) != user.username or user.is_active is not True):
        raise ContractError("AUTHENTICATION_REQUIRED", "Native OIDC login is required", 401)
    username = user.username
    current = CloudFileOIDCBackend().get_user(username)
    if current is None:
        raise ContractError("AUTHENTICATION_REQUIRED", "Native download identity is unavailable", 401)
    try:
        profile = Profile.objects.get(user=username)
        actor = AuthenticatedPolicyActor(profile.login_id, username)
        reverse = Profile.objects.get(login_id=actor.user_id)
        if reverse.user != username:
            raise ContractError("AUTHENTICATION_REQUIRED", "Native identity binding changed", 401)
        return actor
    except (Profile.DoesNotExist, MultipleObjectsReturned):
        raise ContractError("AUTHENTICATION_REQUIRED", "Native download identity is unavailable", 401) from None


class OIDCReadTicketFactory:
    def __init__(self, resources):
        if not isinstance(resources, LoginResources):
            raise ValueError("actual login resources required")
        self.resources = resources

    @contextmanager
    def __call__(self, request, request_id):
        actor = native_download_actor(request)
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
            reference = resource_ref(body["reference"])
            operation = body.get("operation", "download")
            if reference["kind"] != "file" or operation not in ("view", "download"):
                raise invalid("Download tickets require a file and supported read operation")
            if not isinstance(self.service_factory, OIDCReadTicketFactory):
                raise ContractError("POLICY_UNAVAILABLE", "Download ticket runtime is unavailable", 503)
            with self.service_factory(request, request_id) as issuer:
                config = settings.CLOUDFILE_POLICY_CONFIG
                preflight = ContentReadAuthority(issuer.preparation, PolicyCore(config['core_library']),
                    request_id=request_id, cloud_mode=config['cloud_mode'])
                try:
                    preflight.consume(reference, lambda cursor, target: None)
                except ContractError as error:
                    if error.code == 'ACCESS_DENIED':
                        record_transfer(issuer.authority.resources.resources, issuer.preparation.actor,
                            reference, request_id, 'file.' + operation, 'denied', reason=error.code,
                            client_ip=audit_peer_ip(request))
                    raise
                result = issuer.issue(request, reference, operation=operation)
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


def oidc_read_ticket_routes(*, resources):
    """For explicit trusted URL inclusion only; never installs itself."""
    from django.urls import path
    factory = OIDCReadTicketFactory(resources)
    return [path("read-tickets/", OIDCReadTicketView.as_view(service_factory=factory),
        name="cloudfile-oidc-read-ticket")]
