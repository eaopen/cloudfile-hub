"""Fixed machine action/provider grants, not an impersonated user session."""
from contextlib import contextmanager
from types import MappingProxyType

from ..authorization.resources import PolicyResources
from ..common.errors import ContractError
from ..common.validation import identifier
from ..identity.service_tokens import ServiceTokenVerifier
from .refresh_management import UserRefreshManagement
from .refresh_worker import UserRefreshJob


class ServiceRefreshFactory:
    def __init__(self, *, verifier, resources, provider_grants):
        if (not isinstance(verifier, ServiceTokenVerifier) or not isinstance(resources, PolicyResources)
                or not isinstance(provider_grants, dict) or not provider_grants):
            raise ValueError("actual verifier, owned policy resources and fixed grants required")
        grants = {}
        for service, providers in provider_grants.items():
            identifier(service)
            if not isinstance(providers, frozenset) or not providers:
                raise ValueError("fixed service provider grants required")
            for provider in providers:
                identifier(provider, maximum=32)
            grants[service] = providers
        self.verifier, self.resources = verifier, resources
        self.grants = MappingProxyType(grants)

    @contextmanager
    def __call__(self, request, request_id):
        identifier(request_id)
        principal = self.verifier.verify(request.headers.get("Authorization"))
        principal.require(UserRefreshJob.KIND)
        providers = self.grants.get(principal.service_id, frozenset())
        if self.resources.provider not in providers:
            raise ContractError("ACCESS_DENIED", "Service refresh provider is not allowed", 403)
        with self.resources.connection() as connection:
            yield UserRefreshManagement(connection, actor=principal, provider=self.resources.provider,
                native_schema=self.resources.native_schema, identity_schema=self.resources.identity_schema,
                service_providers=providers)
