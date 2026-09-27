"""Post-fork host lifecycle owner; no routes or authorization enablement."""
from contextlib import contextmanager
import os
import threading

from ..common.errors import ContractError
from .deployment import configure_policy


class PolicyHost:
    def __init__(self, settings, *, directory_authorization, resource_secret=None, lifecycle_reader=None,
                 audit_secret=None, audit_redact=None, audit_result_root=None,
                 refresh_service_verifier=None, refresh_provider_grants=None,
                 oidc=None, oidc_jit_enabled=False, local_edit_instance=None,
                 local_edit_version_reader=None):
        # Construct after the server worker fork, never in a preload parent.
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.active = 0
        self.draining = False
        self.closed = False
        self.deployment = configure_policy(settings, directory_authorization=directory_authorization,
            resource_secret=resource_secret, lifecycle_reader=lifecycle_reader,
            audit_secret=audit_secret, audit_redact=audit_redact, audit_result_root=audit_result_root,
            refresh_service_verifier=refresh_service_verifier, refresh_provider_grants=refresh_provider_grants,
            oidc=oidc, oidc_jit_enabled=oidc_jit_enabled,
            local_edit_instance=local_edit_instance,
            local_edit_version_reader=local_edit_version_reader)

    @contextmanager
    def login_resources_scope(self):
        # Cover the entire HTTP adapter, not just runtime(): RP/browser logout
        # also accesses Redis outside the login SQL scope. Never drain that pool
        # while one of those request operations remains in flight.
        self._process()
        with self.lock:
            if self.draining or self.closed:
                raise ContractError("IDENTITY_UNAVAILABLE", "Login host is draining", 503)
            self.active += 1
        try:
            from ..identity.resources import LoginResources
            resources = self.deployment.login_resources
            if not isinstance(resources, LoginResources):
                raise ContractError("IDENTITY_UNAVAILABLE", "Login runtime is not configured", 503)
            yield resources
        finally:
            with self.lock:
                self.active -= 1

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

    def context_service(self, request, request_id):
        return self._service(request, request_id, resource=False, context=True)

    def refresh_service(self, request, request_id):
        return self._service(request, request_id, resource=False, refresh=True)

    def machine_refresh_service(self, request, request_id):
        return self._service(request, request_id, resource=False, machine_refresh=True)

    def local_session_service(self, request, request_id):
        return self._service(request, request_id, resource=False, local_session=True)

    def local_device_service(self, request, request_id):
        return self._service(request, request_id, resource=False, local_device=True)

    @contextmanager
    def _service(self, request, request_id, *, resource, audit=False, context=False, refresh=False,
                 machine_refresh=False, local_session=False, local_device=False):
        self._process()
        with self.lock:
            if self.draining or self.closed:
                raise ContractError("POLICY_UNAVAILABLE", "Policy host is draining", 503)
            self.active += 1
        try:
            if local_session:
                factory = self.deployment.local_session_factory
            elif local_device:
                factory = self.deployment.local_device_factory
            elif machine_refresh:
                factory = self.deployment.service_refresh_factory
            elif refresh:
                factory = self.deployment.refresh_factory
            elif context:
                factory = self.deployment.context_factory
            elif audit:
                factory = self.deployment.audit_factory
            else:
                factory = self.deployment.resource_factory if resource else self.deployment.factory
            if factory is None:
                raise ContractError("RESOURCE_UNAVAILABLE", "Resource runtime is not configured", 503)
            with factory(request, request_id) as service:
                yield service
        finally:
            with self.lock:
                self.active -= 1

    def local_agent_call(self, operation, value, request_id):
        return self._local_agent_call("local_agent_runtime", operation, value, request_id)

    def local_read_ticket(self, value, request_id):
        return self._local_agent_call("local_read_issuer", "issue", value, request_id)

    def _local_agent_call(self, runtime_name, operation, value, request_id):
        self._process()
        with self.lock:
            if self.draining or self.closed:
                raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Local edit host is draining", 503)
            self.active += 1
        try:
            runtime = getattr(self.deployment, runtime_name, None)
            method = getattr(runtime, operation, None)
            if not callable(method):
                raise ContractError("LOCAL_SESSION_UNAVAILABLE", "Local edit runtime is unavailable", 503)
            return method(value, request_id)
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
