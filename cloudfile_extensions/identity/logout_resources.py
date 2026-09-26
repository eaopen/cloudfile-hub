"""Owned backchannel intake independent of employee-directory availability."""
from contextlib import contextmanager

from ..common.http import HttpsJsonClient
from ..jobs.store import JobStore
from .resources import LoginResources
from .oidc import SigningKeys
from .logout_token import LogoutTokenValidator
from .logout_jobs import BackchannelJobs
from .session_delete import NativeDBSessionDelete


class LogoutResources:
    def __init__(self, login_resources, *, enabled=False):
        if not isinstance(login_resources, LoginResources) or enabled is not True:
            raise ValueError("actual login resources and explicit backchannel enablement required")
        self.resources = login_resources

    @contextmanager
    def intake(self):
        resources = self.resources
        with resources.resources.connection() as connection:
            client = HttpsJsonClient(maximum_bytes=65536, ca_bundle=resources.oidc.ca_bundle)
            try:
                jobs = BackchannelJobs(JobStore(connection), LogoutTokenValidator(resources.oidc,
                    SigningKeys(resources.oidc.jwks_url, client=client)))
                # Refuse acceptance into a backend this deployment cannot drain.
                # This proves the actual native DB location, not worker liveness.
                NativeDBSessionDelete(jobs.index, identity_schema=resources.resources.identity_schema)
                yield jobs
            finally:
                client.session.close()
