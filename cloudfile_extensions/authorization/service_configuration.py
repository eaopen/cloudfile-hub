"""Validate primitive deployment values before constructing service security objects."""

from dataclasses import dataclass
import re

from ..common.validation import identifier, object_fields
from ..identity.service_revocations import ServiceRevocations
from ..identity.service_tokens import ServiceCredential, ServiceTokenVerifier
from ..identity.user_delegation import DelegationKey


@dataclass(frozen=True)
class ServiceRuntimeConfiguration:
    credentials: dict
    provider_grants: dict
    signing_keys: dict
    revocation_prefix: str

    def build(self, redis):
        revocations = ServiceRevocations(redis, prefix=self.revocation_prefix)
        verifier = ServiceTokenVerifier(self.credentials, revocations=revocations)
        return verifier, self.provider_grants, verifier, self.signing_keys


def _secret(value, message):
    if (not isinstance(value, str) or len(value.encode("utf-8")) < 32
            or len(value) > 4096 or "\x00" in value):
        raise ValueError(message)
    return value.encode("utf-8")


def _string_set(value, message, *, maximum=128):
    if not isinstance(value, list) or not value:
        raise ValueError(message)
    result = frozenset(value)
    if len(result) != len(value):
        raise ValueError(message)
    for item in result:
        identifier(item, maximum=maximum)
    return result


def directory_authorization(configured, explicit):
    token = configured.get("directory_bearer_token")
    if explicit is not None and token is not None:
        raise ValueError("directory authorization is configured twice")
    if explicit is not None:
        if not callable(explicit):
            raise ValueError("machine directory credential supplier required")
        return explicit
    if (not isinstance(token, str) or not 1 <= len(token) <= 4096
            or not re.fullmatch(r"[\x21-\x7e]+", token)):
        raise ValueError("machine directory credential supplier required")
    header = "Bearer " + token
    return lambda: header


def parse_service_runtime(configured, *, provider):
    keys = ("service_credentials", "refresh_provider_grants", "delegation_signing_keys")
    present = [key in configured for key in keys]
    if not any(present):
        return None
    if not all(present):
        raise ValueError("complete service credential, refresh grant and delegation key configuration required")
    credentials_value = configured["service_credentials"]
    grants_value = configured["refresh_provider_grants"]
    delegation_value = configured["delegation_signing_keys"]
    if not all(isinstance(value, dict) and value for value in
               (credentials_value, grants_value, delegation_value)):
        raise ValueError("non-empty service security mappings required")

    credentials = {}
    for kid, value in credentials_value.items():
        identifier(kid, maximum=64)
        object_fields(value, ("service_id", "issuer", "audience", "secret", "scopes"),
                      ("maximum_ttl",))
        ttl = value.get("maximum_ttl", 300)
        credentials[kid] = ServiceCredential(value["service_id"], value["issuer"],
            value["audience"], _secret(value["secret"], "invalid service credential secret"),
            _string_set(value["scopes"], "invalid service credential scopes"), ttl)

    grants = {}
    for service_id, providers in grants_value.items():
        identifier(service_id)
        grants[service_id] = _string_set(providers, "invalid refresh provider grants", maximum=32)
        if service_id not in {credential.service_id for credential in credentials.values()}:
            raise ValueError("refresh grant service has no credential")

    signing_keys = {}
    for service_id, value in delegation_value.items():
        identifier(service_id)
        object_fields(value, ("kid", "issuer", "audience", "secret"))
        kid = value["kid"]
        identifier(kid, maximum=64)
        if service_id not in grants:
            raise ValueError("delegation service has no refresh grant")
        signing_keys[service_id] = (kid, DelegationKey(service_id, value["issuer"],
            value["audience"], provider,
            _secret(value["secret"], "invalid delegation signing secret")))

    prefix = configured.get("service_revocation_prefix", "cf:service-revocations:")
    # Validate the namespace without allocating or contacting Redis.
    ServiceRevocations(object(), prefix=prefix)
    return ServiceRuntimeConfiguration(credentials, grants, signing_keys, prefix)
