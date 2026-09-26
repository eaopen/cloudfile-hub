"""Prebound OIDC authentication followed by mandatory own-subject preparation.

Does not create a browser session, JIT account or authorization ticket. The
native login adapter may consume the result only after its own final checks.
"""
from dataclasses import dataclass
import time

from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from .oidc import OIDCFlow
from .sql_bindings import SQLIdentityBindings
from .jit import SQLJITProvisioner
from .provisioning import ProvisioningJobs


@dataclass(frozen=True)
class PreparedLogin:
    user_id: str
    username: str
    context_epoch: str
    redirect: str


@dataclass(frozen=True)
class PendingLogin:
    job_id: str


class PreparedOIDCLogin:
    def __init__(self, flow, bindings, *, preparation_factory, jit=None, provisioning=None):
        if not isinstance(flow, OIDCFlow) or not isinstance(bindings, SQLIdentityBindings) or not callable(preparation_factory):
            raise ValueError("native OIDC flow, bindings and preparation factory required")
        self.flow, self.bindings, self.preparation_factory = flow, bindings, preparation_factory
        if jit is not None and (not isinstance(jit, SQLJITProvisioner) or jit.bindings is not bindings):
            raise ValueError("JIT must share the exact native binding adapter")
        self.jit = jit
        if provisioning is not None and (not isinstance(provisioning, ProvisioningJobs) or
                                         provisioning.jit.bindings is not bindings):
            raise ValueError("provisioning must share the exact native binding adapter")
        if jit is not None and provisioning is not None:
            raise ValueError("choose durable provisioning or synchronous JIT, not both")
        self.provisioning = provisioning

    def begin(self, binding, *, redirect="/"):
        return self.flow.begin(binding, redirect=redirect)

    def complete(self, *, state, code, binding):
        # Only OIDCFlow's token/state/nonce/PKCE validation establishes identity.
        identity, redirect = self.flow.complete(state=state, code=code, binding=binding)
        if type(identity.get("expires_at")) is not int or identity["expires_at"] <= time.time():
            raise ContractError("AUTHENTICATION_REQUIRED", "OIDC authentication expired", 401)
        username = self.bindings.resolve(issuer=identity["issuer"], subject=identity["sub"],
                                         user_id=identity["userId"])
        if self.provisioning is not None:
            job_id = self.provisioning.request_for_login(identity, unbound=username is None)
            if job_id is not None:
                return PendingLogin(job_id)
        if username is None:
            if self.jit is None:
                raise ContractError("IDENTITY_NOT_FOUND", "Business identity has not been bound", 409)
            username = self.jit.ensure(identity)
        preparation = self.preparation_factory(identity["userId"])
        if not isinstance(preparation, SubjectPreparation) or preparation.actor != identity["userId"]:
            raise ContractError("IDENTITY_UNAVAILABLE", "Login preparation is unavailable", 503)
        context = preparation.prepare(identity["userId"], trigger="login")
        # Recheck binding after source I/O/projection, not just before it.
        current = self.bindings.resolve(issuer=identity["issuer"], subject=identity["sub"],
                                        user_id=identity["userId"])
        if current != username:
            raise ContractError("IDENTITY_UNAVAILABLE", "Login identity changed", 503)
        if identity["expires_at"] <= time.time():
            raise ContractError("AUTHENTICATION_REQUIRED", "OIDC authentication expired", 401)
        return PreparedLogin(identity["userId"], username, context["context_epoch"], redirect)
