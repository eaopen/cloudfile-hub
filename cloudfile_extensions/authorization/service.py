"""Authenticated directory content policy and current-actor diagnosis service.

Runtime actor comes from trusted host authentication, never request JSON.
This service cannot replace whole-library policy or invoke recovery authority.
"""
import re
from functools import wraps
from uuid import UUID

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import resource_ref
from .management import DirectoryManagement


def safe_errors(method):
    @wraps(method)
    def invoke(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except ContractError:
            raise
        except Exception:
            raise ContractError("POLICY_UNAVAILABLE", "Policy service is unavailable", 503) from None
    return invoke


class DirectoryPolicyService:
    def __init__(self, management):
        if not isinstance(management, DirectoryManagement):
            raise ValueError("real library authority required")
        self.management = management

    @safe_errors
    def effective(self, request):
        from .read import ContentReadAuthority
        object_fields(request, ("reference",))
        reference = resource_ref(request["reference"])
        authority = ContentReadAuthority(self.management.preparation, self.management.core,
            request_id=self.management.rules.request_id, cloud_mode=self.management.native_qualification.cloud_mode)
        return authority.inspect_policy(reference)

    @staticmethod
    def _domain(domain):
        if not isinstance(domain, str) or domain != "acl":
            raise invalid("Invalid policy domain")

    @staticmethod
    def _key(key):
        if key is None:
            raise ContractError("IDEMPOTENCY_REQUIRED", "Idempotency-Key is required", 400)
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key):
            raise invalid("Invalid idempotency key")
        return key

    @staticmethod
    def _id(value):
        try:
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise ValueError()
        except (ValueError, AttributeError):
            raise invalid("Invalid policy rule ID") from None
        return value

    @staticmethod
    def _condition(value):
        if value is None:
            raise ContractError("PRECONDITION_REQUIRED", "If-Match is required", 428)
        if (not isinstance(value, str) or len(value) > 2048 or
                any(not re.fullmatch(r'"[^"\r\n]+"', part.strip()) for part in value.split(","))):
            raise invalid("A strong If-Match validator is required")
        return value

    def _request(self, request, *, with_value):
        object_fields(request, ("reference", "value") if with_value else ("reference",))
        reference = resource_ref(request["reference"])
        if not with_value:
            return reference, None
        store = self.management.rules
        value = store.validate(request["value"])
        if (reference["path"], reference["kind"]) != (value["path"], value["kind"]):
            raise invalid("Policy target mismatch")
        return reference, value

    @safe_errors
    def list(self, domain, request, *, limit=50, after=None):
        self._domain(domain)
        reference, _ = self._request(request, with_value=False)
        return self.management.list_target(reference, limit=limit, after=after)

    @safe_errors
    def create(self, domain, request, *, idempotency_key):
        return self._mutate(domain, request, idempotency_key=idempotency_key)

    @safe_errors
    def replace(self, domain, rule_id, request, *, if_match, idempotency_key):
        return self._mutate(domain, request, rule_id=self._id(rule_id),
            if_match=self._condition(if_match), idempotency_key=idempotency_key)

    @safe_errors
    def delete(self, domain, rule_id, request, *, if_match, idempotency_key):
        return self._mutate(domain, request, rule_id=self._id(rule_id),
            if_match=self._condition(if_match), idempotency_key=idempotency_key, deleting=True)

    def _mutate(self, domain, request, *, idempotency_key, rule_id=None, if_match=None, deleting=False):
        self._domain(domain)
        key = self._key(idempotency_key)
        reference, value = self._request(request, with_value=not deleting)
        mutate = self.management.mutate
        return mutate(reference, value=value, rule_id=rule_id, if_match=if_match, idempotency_key=key)
