"""Optional Gunicorn worker hooks; no public policy routes are enabled."""
import os

from ..common.errors import ContractError
from .host import PolicyHost

_host = None


def post_worker_init(worker):
    """Called after the worker has loaded Django, never in the preload master."""
    global _host
    from django.conf import settings
    local_edit_enabled = getattr(settings, "CLOUDFILE_LOCAL_EDIT_ENABLED", False)
    config = getattr(settings, "CLOUDFILE_POLICY_CONFIG", None)
    if config is None:
        if local_edit_enabled:
            raise RuntimeError("CloudFile local edit requires the post-fork policy worker")
        _host = None
        return
    if _host is not None and _host.pid == os.getpid():
        raise RuntimeError("CloudFile policy worker is already initialized")
    # An inherited host belongs to the parent; do not acquire its lock or close
    # its sockets. A fresh post-fork host owns this worker's resources.
    _host = None
    authorization = getattr(settings, "CLOUDFILE_DIRECTORY_AUTHORIZATION", None)
    try:
        _host = PolicyHost(config, directory_authorization=authorization,
            resource_secret=getattr(settings, "CLOUDFILE_RESOURCE_SECRET", None),
            lifecycle_reader=getattr(settings, "CLOUDFILE_RESOURCE_LIFECYCLE_READER", None),
            audit_secret=getattr(settings, "CLOUDFILE_AUDIT_CURSOR_SECRET", None),
            audit_redact=getattr(settings, "CLOUDFILE_AUDIT_REDACT", None),
            audit_result_root=getattr(settings, "CLOUDFILE_AUDIT_RESULT_ROOT", None),
            refresh_service_verifier=getattr(settings, "CLOUDFILE_REFRESH_SERVICE_VERIFIER", None),
            refresh_provider_grants=getattr(settings, "CLOUDFILE_REFRESH_PROVIDER_GRANTS", None),
            oidc=getattr(settings, "CLOUDFILE_OIDC_CONFIG", None),
            oidc_jit_enabled=getattr(settings, "CLOUDFILE_OIDC_JIT_ENABLED", False),
            local_edit_instance=getattr(settings, "CLOUDFILE_LOCAL_EDIT_INSTANCE", None),
            local_edit_version_reader=getattr(settings, "CLOUDFILE_LOCAL_EDIT_VERSION_READER", None),
            local_edit_enabled=local_edit_enabled)
    except Exception:
        raise RuntimeError("CloudFile policy worker initialization failed; check trusted configuration") from None


def policy_service(request, request_id):
    """Trusted view factory; not a Django route or feature readiness assertion."""
    if _host is None or _host.pid != os.getpid():
        raise ContractError("POLICY_UNAVAILABLE", "Policy worker is unavailable", 503)
    return _host.service(request, request_id)


def login_resources_scope():
    """Late post-fork resolution for explicitly mounted hosted login routes."""
    if _host is None or _host.pid != os.getpid():
        raise ContractError("IDENTITY_UNAVAILABLE", "Login worker is unavailable", 503)
    return _host.login_resources_scope()


def resource_service(request, request_id):
    """Owned resource scope; requires the trusted native lifecycle adapter."""
    if _host is None or _host.pid != os.getpid():
        raise ContractError("RESOURCE_UNAVAILABLE", "Resource worker is unavailable", 503)
    return _host.resource_service(request, request_id)


def audit_service(request, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("AUDIT_UNAVAILABLE", "Audit worker is unavailable", 503)
    return _host.audit_service(request, request_id)


def context_service(request, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("SUBJECT_UNAVAILABLE", "Context worker is unavailable", 503)
    return _host.context_service(request, request_id)


def refresh_service(request, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("SUBJECT_UNAVAILABLE", "Refresh worker is unavailable", 503)
    return _host.refresh_service(request, request_id)


def machine_refresh_service(request, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("SUBJECT_UNAVAILABLE", "Refresh worker is unavailable", 503)
    return _host.machine_refresh_service(request, request_id)


def local_session_service(request, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Local edit worker is unavailable", 503)
    return _host.local_session_service(request, request_id)


def local_device_service(request, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("DEVICE_UNAVAILABLE", "Local device worker is unavailable", 503)
    return _host.local_device_service(request, request_id)


def local_agent_call(operation, value, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Local edit worker is unavailable", 503)
    return _host.local_agent_call(operation, value, request_id)


def local_read_ticket(value, request_id):
    if _host is None or _host.pid != os.getpid():
        raise ContractError("LOCAL_READ_UNAVAILABLE", "Local read worker is unavailable", 503)
    return _host.local_read_ticket(value, request_id)


def worker_exit(server, worker):
    global _host
    if _host is None or _host.pid != os.getpid():
        return
    host = _host
    host.drain()
    try:
        host.close()
    except ContractError:
        # Do not disconnect active scopes or log credentials/internal exceptions.
        # The process supervisor owns forced termination of unfinished requests.
        worker.log.warning("CloudFile policy worker exited before request drain completed")
        return
    _host = None
