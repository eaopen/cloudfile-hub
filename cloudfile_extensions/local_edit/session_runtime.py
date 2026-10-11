"""Native browser-owned local-session assembly; no Agent token authenticator."""
from contextlib import contextmanager

from ..resources.runtime import ResourceServiceFactory
from ..authorization.runtime import AuthenticatedPolicyActor
from ..common.errors import ContractError
from .device_proof import DeviceChallenge
from .session_service import LocalSessionService


class LocalSessionFactory:
    def __init__(self, resources, *, instance, version_reader, locks=None, agent2_exclusive_enabled=False):
        if not isinstance(resources, ResourceServiceFactory) or not callable(version_reader):
            raise ValueError("actual resource factory and protected version adapter required")
        if locks is not None:
            raise ValueError('Legacy local editing locks are no longer supported')
        DeviceChallenge(instance, "11111111-1111-4111-8111-111111111111",
            "11111111-1111-4111-8111-111111111111", "claim", "A" * 43, 1, 61, "0" * 64).message()
        if len(instance) > 255:
            raise ValueError("bounded fixed instance origin required")
        self.resources, self.instance, self.version_reader, self.locks = resources, instance, version_reader, locks
        if type(agent2_exclusive_enabled) is not bool:
            raise ValueError('Agent2 exclusive flag must be a boolean')
        self.agent2_exclusive_enabled = agent2_exclusive_enabled

    @contextmanager
    def __call__(self, request, request_id):
        actor = self.resources.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Native local-session browser identity required", 401)
        with self.resources(request, request_id) as resources:
            yield LocalSessionService(resources, actor=actor, instance=self.instance,
                version_reader=self.version_reader, agent2_exclusive_enabled=self.agent2_exclusive_enabled)
