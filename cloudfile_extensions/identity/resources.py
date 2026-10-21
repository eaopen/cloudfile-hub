"""Owned login assembly for trusted native callback hosts, not authentication."""
from contextlib import contextmanager

from ..authorization.resources import PolicyResources
from ..directory.provider import DirectoryProvider
from .oidc import OIDCConfig
from .runtime import LoginRuntime


class LoginResources:
    def __init__(self, policy_resources, *, oidc, jit_enabled=False, prefix="cf:"):
        if (not isinstance(policy_resources, PolicyResources) or not isinstance(oidc, OIDCConfig)
                or type(jit_enabled) is not bool):
            raise ValueError("actual policy resources and trusted OIDC configuration required")
        # Login flow and subject preparation must address exactly the same
        # namespace as resource authority and background refresh workers.
        if not isinstance(prefix, str) or policy_resources.prefix != prefix + "subjects:":
            raise ValueError("login and policy subject namespaces must match")
        self.resources, self.oidc = policy_resources, oidc
        self.jit_enabled, self.prefix = jit_enabled, prefix

    @contextmanager
    def runtime(self, request_id):
        with self.resources.connection() as connection:
            directory = self.resources.directory_factory()
            if not isinstance(directory, DirectoryProvider):
                raise ValueError("actual owned directory provider required")
            runtime = None
            try:
                runtime = LoginRuntime(connection, self.resources.redis, oidc=self.oidc,
                    directory=directory, provider_id=self.resources.provider,
                    native_schema=self.resources.native_schema,
                    identity_schema=self.resources.identity_schema,
                    request_id=request_id, jit_enabled=self.jit_enabled, prefix=self.prefix)
                yield runtime
            finally:
                try:
                    if runtime is not None:
                        runtime.close()
                finally:
                    directory.client.session.close()
