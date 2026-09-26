"""Trusted request/worker assembly. No session finalizer or public registration.

The caller owns one dedicated, non-reconnecting SQL connection and Redis client.
Never share an instance between threads or register its handler before native
entry-point guards are installed. Configuration comes from deployment, not HTTP.
"""
from ..common.errors import ContractError
from ..common.http import HttpsJsonClient
from ..common.validation import identifier
from ..directory.preparation import SubjectPreparation
from ..directory.provider import DirectoryProvider
from ..jobs.store import JobStore
from ..schema.runner import SchemaRunner
from .browser_binding import BrowserLoginBindings
from .jit import SQLJITProvisioner
from .login import PreparedOIDCLogin
from .oidc import OIDCConfig, OIDCFlow, RedisLoginFlows, SigningKeys, IDTokenValidator
from .pending import PendingLoginProofs, PendingLoginStatus
from .provisioning import ProvisioningJobs
from .sql_bindings import SQLIdentityBindings


class LoginRuntime:
    def __init__(self, connection, redis, *, oidc, directory, provider_id,
                 native_schema, identity_schema, request_id, jit_enabled=False,
                 prefix="cf:"):
        if (not isinstance(oidc, OIDCConfig) or not isinstance(directory, DirectoryProvider)
                or type(jit_enabled) is not bool):
            raise ValueError("trusted OIDC and directory configuration required")
        identifier(request_id)
        identifier(provider_id, maximum=32)
        if (not isinstance(prefix, str) or not prefix.endswith(":") or
                not 1 <= len(prefix) <= 128 or not prefix.isascii() or
                any(not (char.isalnum() or char in ":_-.") for char in prefix)):
            raise ValueError("fixed deployment Redis namespace required")
        SchemaRunner(connection).require_current()
        self.connection, self.redis = connection, redis
        self.directory, self.provider = directory, provider_id
        self.native_schema, self.identity_schema = native_schema, identity_schema
        self.request_id, self.prefix = request_id, prefix
        # This adapter may resolve bindings but must never grant management writes.
        def reject_management(*args):
            raise ContractError("ACCESS_DENIED", "Login cannot manage identity bindings", 403)
        self.bindings = SQLIdentityBindings(connection, native_schema=native_schema,
            identity_schema=identity_schema, directory_provider=provider_id,
            authorize=reject_management, audit=reject_management)
        self.store = JobStore(connection)
        self.jit = SQLJITProvisioner(self.bindings, issuer=oidc.issuer,
            directory=directory, enabled=jit_enabled, request_id=request_id)
        self.provisioning = ProvisioningJobs(self.store, self.jit,
            preparation_factory=self.preparation)
        self.browser = BrowserLoginBindings(redis, prefix=prefix + "oidc:browser:")
        self.proofs = PendingLoginProofs(redis, prefix=prefix + "oidc:pending:",
            browser_bindings=self.browser)
        self.pending = PendingLoginStatus(self.proofs, self.provisioning)
        keys = SigningKeys(oidc.jwks_url, client=HttpsJsonClient(
            maximum_bytes=65536, ca_bundle=oidc.ca_bundle))
        self.flow = OIDCFlow(oidc, RedisLoginFlows(redis, prefix=prefix + "oidc:flow:"),
            IDTokenValidator(oidc, keys))
        self.login = PreparedOIDCLogin(self.flow, self.bindings,
            preparation_factory=self.preparation, provisioning=self.provisioning,
            pending_proofs=self.proofs)

    def preparation(self, user_id):
        return SubjectPreparation(self.connection, self.redis, provider_id=self.provider,
            directory=self.directory, native_schema=self.native_schema,
            identity_schema=self.identity_schema, actor_user_id=user_id,
            request_id=self.request_id, prefix=self.prefix + "subjects:")
