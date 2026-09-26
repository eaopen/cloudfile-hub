"""Explicit fixed JIT worker; does not install callbacks or create sessions."""
from contextlib import ExitStack
from uuid import uuid4

from ..authorization.resources import PolicyResources
from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from ..directory.provider import DirectoryProvider
from ..jobs.runtime import run_loop
from ..jobs.store import JobStore
from ..jobs.worker import JobWorker
from .jit import SQLJITProvisioner
from .provisioning import ProvisioningJobs
from .sql_bindings import SQLIdentityBindings


class ProvisioningBackground:
    def __init__(self, resources, *, issuer, owner, enabled=False, lease_seconds=30):
        if not isinstance(resources, PolicyResources) or enabled is not True:
            raise ValueError("actual policy resources and explicit JIT enablement required")
        self.stack = ExitStack()
        self.closed = self.running = False
        try:
            connection = self.stack.enter_context(resources.connection())
            directory = resources.directory_factory()
            if not isinstance(directory, DirectoryProvider):
                raise ValueError("actual owned directory provider required")
            self.stack.callback(directory.client.session.close)
            # A worker may reconcile its authenticated provisioning requests,
            # never exercise general identity-binding management authority.
            def reject(*args):
                raise ContractError("ACCESS_DENIED", "Provisioning cannot manage identity bindings", 403)
            bindings = SQLIdentityBindings(connection, native_schema=resources.native_schema,
                identity_schema=resources.identity_schema, directory_provider=resources.provider,
                authorize=reject, audit=reject)
            jit = SQLJITProvisioner(bindings, issuer=issuer, directory=directory,
                enabled=True, request_id=str(uuid4()))
            def task_preparation(user, request_id):
                return SubjectPreparation(connection, resources.redis, provider_id=resources.provider,
                    directory=directory, native_schema=resources.native_schema,
                    identity_schema=resources.identity_schema, actor_user_id=user,
                    request_id=request_id, prefix=resources.prefix)
            self.pipeline = ProvisioningJobs(JobStore(connection), jit,
                preparation_factory=lambda user: task_preparation(user, str(uuid4())),
                task_preparation_factory=task_preparation)
            self.worker = JobWorker(self.pipeline.store, owner=owner,
                handlers={ProvisioningJobs.KIND: self.pipeline.handler}, lease_seconds=lease_seconds)
        except Exception:
            self.close()
            raise

    def run_once(self):
        if self.closed or self.running:
            raise RuntimeError("provisioning background is closed or already running")
        self.running = True
        try:
            return self.worker.run_once()
        except Exception:
            self.running = False
            self.close()
            raise
        finally:
            self.running = False

    def run(self, stop, *, poll_seconds=2, once=False, emit=lambda value: None):
        try:
            return run_loop(self, stop, poll_seconds=poll_seconds, once=once, emit=emit)
        finally:
            self.close()

    def close(self):
        if self.running:
            raise RuntimeError("finish active provisioning before shutdown")
        if not self.closed:
            self.closed = True
            self.stack.close()

    def __enter__(self):
        if self.closed:
            raise RuntimeError("provisioning background is closed")
        return self

    def __exit__(self, *args):
        self.close()
