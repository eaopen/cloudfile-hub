"""Prebound OIDC authentication followed by mandatory own-subject preparation.

Does not create a browser session, JIT account or authorization ticket. The
native login adapter may consume the result only after its own final checks.
"""
from dataclasses import dataclass

from ..common.errors import ContractError
from ..directory.preparation import SubjectPreparation
from .oidc import OIDCFlow
from .sql_bindings import SQLIdentityBindings


@dataclass(frozen=True)
class PreparedLogin:
    user_id: str
    username: str
    context_epoch: str
    redirect: str


class PreparedOIDCLogin:
    def __init__(self, flow, bindings, *, preparation_factory):
        if not isinstance(flow, OIDCFlow) or not isinstance(bindings, SQLIdentityBindings) or not callable(preparation_factory):
            raise ValueError("native OIDC flow, bindings and preparation factory required")
        self.flow, self.bindings, self.preparation_factory = flow, bindings, preparation_factory

    def begin(self, binding, *, redirect="/"):
        return self.flow.begin(binding, redirect=redirect)

    def complete(self, *, state, code, binding):
        # Only OIDCFlow's token/state/nonce/PKCE validation establishes identity.
        identity, redirect = self.flow.complete(state=state, code=code, binding=binding)
        username = self.bindings.resolve(issuer=identity["issuer"], subject=identity["sub"],
                                         user_id=identity["userId"])
        if username is None:
            raise ContractError("IDENTITY_NOT_FOUND", "Business identity has not been bound", 409)
        preparation = self.preparation_factory(identity["userId"])
        if not isinstance(preparation, SubjectPreparation) or preparation.actor != identity["userId"]:
            raise ContractError("IDENTITY_UNAVAILABLE", "Login preparation is unavailable", 503)
        context = preparation.prepare(identity["userId"], trigger="login")
        # Recheck binding after source I/O/projection, not just before it.
        current = self.bindings.resolve(issuer=identity["issuer"], subject=identity["sub"],
                                        user_id=identity["userId"])
        if current != username:
            raise ContractError("IDENTITY_UNAVAILABLE", "Login identity changed", 503)
        return PreparedLogin(identity["userId"], username, context["context_epoch"], redirect)
