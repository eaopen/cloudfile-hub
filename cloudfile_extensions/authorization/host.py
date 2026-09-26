"""Post-fork host lifecycle owner; no routes or authorization enablement."""
from contextlib import contextmanager
import os
import threading

from ..common.errors import ContractError
from .deployment import configure_policy


class PolicyHost:
    def __init__(self, settings, *, directory_authorization, resource_secret=None, lifecycle_reader=None,
                 audit_secret=None, audit_redact=None, audit_result_root=None):
        # Construct after the server worker fork, never in a preload parent.
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.active = 0
        self.draining = False
        self.closed = False
        self.deployment = configure_policy(settings, directory_authorization=directory_authorization,
            resource_secret=resource_secret, lifecycle_reader=lifecycle_reader,
            audit_secret=audit_secret, audit_redact=audit_redact, audit_result_root=audit_result_root)

    def _process(self):
        # Check before acquiring an inherited lock that may have been held at
        # fork. Child must initialize its own host, not close the parent's pool.
        if os.getpid() != self.pid:
            raise ContractError("POLICY_UNAVAILABLE", "Policy host must be initialized in this worker", 503)

    def service(self, request, request_id):
        return self._service(request, request_id, resource=False)

    def resource_service(self, request, request_id):
        return self._service(request, request_id, resource=True)

    def audit_service(self, request, request_id):
        return self._service(request, request_id, resource=False, audit=True)

    @contextmanager
    def _service(self, request, request_id, *, resource, audit=False):
        self._process()
        with self.lock:
            if self.draining or self.closed:
                raise ContractError("POLICY_UNAVAILABLE", "Policy host is draining", 503)
            self.active += 1
        try:
            factory = self.deployment.audit_factory if audit else (
                self.deployment.resource_factory if resource else self.deployment.factory)
            if factory is None:
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource runtime is not configured", 503)
            with factory(request, request_id) as service:
                yield service
        finally:
            with self.lock:
                self.active -= 1

    def drain(self):
        """Reject new requests; return whether all existing scopes have exited."""
        self._process()
        with self.lock:
            self.draining = True
            return self.active == 0

    def close(self):
        """Nonblocking shutdown; never disconnect an in-flight request's pool."""
        self._process()
        with self.lock:
            self.draining = True
            if self.active:
                raise ContractError("POLICY_BUSY", "Policy requests must drain before shutdown", 503)
            if self.closed:
                return
            self.closed = True
        self.deployment.close()
