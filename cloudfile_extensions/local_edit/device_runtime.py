"""Actual native browser authentication/owned SQL assembly; no Agent bearer."""
from contextlib import contextmanager

from ..authorization.runtime import AuthenticatedPolicyActor, PolicyServiceFactory
from ..common.errors import ContractError
from ..common.validation import identifier
from ..resources.runtime import expected_subject
from .device_proof import DeviceChallenge
from .device_service import DeviceManagementService


class DeviceManagementFactory:
    def __init__(self, policy_factory, *, instance):
        if not isinstance(policy_factory, PolicyServiceFactory):
            raise ValueError("actual native policy factory required")
        # Validate a deployment origin without issuing a usable challenge.
        DeviceChallenge(instance, "11111111-1111-4111-8111-111111111111",
            "11111111-1111-4111-8111-111111111111", "pair", "A" * 43, 1, 61, "0" * 64).message()
        if len(instance) > 255:
            raise ValueError("bounded fixed instance origin required")
        self.policy_factory, self.instance = policy_factory, instance

    @contextmanager
    def __call__(self, request, request_id):
        actor = self.policy_factory.authenticate(request)
        if not isinstance(actor, AuthenticatedPolicyActor):
            raise ContractError("AUTHENTICATION_REQUIRED", "Native browser identity required", 401)
        expected_subject(request, actor)
        identifier(request_id)
        with self.policy_factory.preparation_scope(actor.user_id, request_id) as preparation:
            yield DeviceManagementService(preparation, actor, instance=self.instance, request_id=request_id)
