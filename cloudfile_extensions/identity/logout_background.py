"""Explicit owned database-session logout worker; no automatic activation."""
from contextlib import ExitStack

from ..common.http import HttpsJsonClient
from ..jobs.runtime import run_loop
from ..jobs.store import JobStore
from ..jobs.worker import JobWorker
from .resources import LoginResources
from .oidc import SigningKeys
from .logout_token import LogoutTokenValidator
from .logout_jobs import BackchannelJobs
from .logout_worker import BackchannelWorker
from .session_delete import NativeDBSessionDelete
from .session_retention import OIDCSessionRetention


class LogoutBackground:
    def __init__(self, resources, *, owner, enabled=False, lease_seconds=30, page_size=100):
        if not isinstance(resources, LoginResources) or enabled is not True:
            raise ValueError("actual login resources and explicit logout enablement required")
        self.stack = ExitStack()
        self.closed = self.running = False
        try:
            connection = self.stack.enter_context(resources.resources.connection())
            client = HttpsJsonClient(maximum_bytes=65536, ca_bundle=resources.oidc.ca_bundle)
            self.stack.callback(client.session.close)
            validator = LogoutTokenValidator(resources.oidc,
                SigningKeys(resources.oidc.jwks_url, client=client))
            self.jobs = BackchannelJobs(JobStore(connection), validator)
            deletion = NativeDBSessionDelete(self.jobs.index,
                identity_schema=resources.resources.identity_schema)
            self.pipeline = BackchannelWorker(self.jobs, deletion, page_size=page_size)
            self.retention = OIDCSessionRetention(deletion)
            self.worker = JobWorker(self.jobs.store, owner=owner,
                handlers={BackchannelJobs.KIND: self.pipeline.handler}, lease_seconds=lease_seconds)
        except Exception:
            self.close()
            raise

    def run_once(self):
        if self.closed or self.running:
            raise RuntimeError("logout background is closed or already running")
        self.running = True
        try:
            result = self.worker.run_once()
            if result is None:
                self.retention.run_once()
            return result
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
            raise RuntimeError("finish active logout before shutdown")
        if not self.closed:
            self.closed = True
            self.stack.close()

    def __enter__(self):
        if self.closed:
            raise RuntimeError("logout background is closed")
        return self

    def __exit__(self, *args):
        self.close()
