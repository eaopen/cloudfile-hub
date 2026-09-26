"""Optional Gunicorn worker hooks; no public policy routes are enabled."""
import os

from ..common.errors import ContractError
from .host import PolicyHost

_host = None


def post_worker_init(worker):
    """Called after the worker has loaded Django, never in the preload master."""
    global _host
    from django.conf import settings
    config = getattr(settings, "CLOUDFILE_POLICY_CONFIG", None)
    if config is None:
        _host = None
        return
    if _host is not None and _host.pid == os.getpid():
        raise RuntimeError("CloudFile policy worker is already initialized")
    # An inherited host belongs to the parent; do not acquire its lock or close
    # its sockets. A fresh post-fork host owns this worker's resources.
    _host = None
    authorization = getattr(settings, "CLOUDFILE_DIRECTORY_AUTHORIZATION", None)
    try:
        _host = PolicyHost(config, directory_authorization=authorization)
    except Exception:
        raise RuntimeError("CloudFile policy worker initialization failed; check trusted configuration") from None


def policy_service(request, request_id):
    """Trusted view factory; not a Django route or feature readiness assertion."""
    if _host is None or _host.pid != os.getpid():
        raise ContractError("POLICY_UNAVAILABLE", "Policy worker is unavailable", 503)
    return _host.service(request, request_id)


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
