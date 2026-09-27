"""Primitive deployment configuration must produce the typed post-fork security runtime."""

import os
import unittest
from unittest.mock import Mock

from cloudfile_extensions.authorization.service_configuration import (
    directory_authorization,
    parse_service_runtime,
)
from cloudfile_extensions.authorization.deployment import configure_policy
from cloudfile_extensions.identity.service_tokens import ServiceTokenVerifier
from cloudfile_extensions.identity.user_delegation import DelegationKey


class ServiceConfigurationTests(unittest.TestCase):
    @staticmethod
    def configured():
        return {
            "service_credentials": {
                "machine-kid": {
                    "service_id": "etech-login",
                    "issuer": "etech-login",
                    "audience": "cloudfile-authorization",
                    "secret": "m" * 32,
                    "scopes": ["subject.refresh", "user.delegation.issue"],
                    "maximum_ttl": 120,
                },
            },
            "refresh_provider_grants": {"etech-login": ["etech"]},
            "delegation_signing_keys": {
                "etech-login": {
                    "kid": "delegation-kid",
                    "issuer": "cloudfile",
                    "audience": "cloudfile-download",
                    "secret": "d" * 32,
                },
            },
            "service_revocation_prefix": "cf:test-service-revocations:",
        }

    def test_builds_shared_revocable_verifier_and_dedicated_key(self):
        parsed = parse_service_runtime(self.configured(), provider="etech")
        refresh, grants, delegation, keys = parsed.build(Mock())
        self.assertIsInstance(refresh, ServiceTokenVerifier)
        self.assertIs(refresh, delegation)
        self.assertEqual(grants, {"etech-login": frozenset({"etech"})})
        kid, key = keys["etech-login"]
        self.assertEqual(kid, "delegation-kid")
        self.assertIsInstance(key, DelegationKey)
        self.assertNotEqual(key.secret, refresh.credentials["machine-kid"].secret)
        self.assertIs(refresh.revocations, delegation.revocations)

    def test_partial_duplicate_and_unbound_service_configuration_is_rejected(self):
        value = self.configured()
        for missing in ("service_credentials", "refresh_provider_grants", "delegation_signing_keys"):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                parse_service_runtime({key: item for key, item in value.items() if key != missing},
                                      provider="etech")
        duplicate = self.configured()
        duplicate["service_credentials"]["other-kid"] = dict(
            duplicate["service_credentials"]["machine-kid"])
        duplicate["service_credentials"]["other-kid"]["service_id"] = "other"
        duplicate["refresh_provider_grants"] = {"missing": ["etech"]}
        with self.assertRaises(ValueError):
            parse_service_runtime(duplicate, provider="etech")

    def test_directory_bearer_is_fixed_and_cannot_override_callable(self):
        supplier = directory_authorization({"directory_bearer_token": "opaque-token"}, None)
        self.assertEqual(supplier(), "Bearer opaque-token")
        with self.assertRaises(ValueError):
            directory_authorization({"directory_bearer_token": "token"}, Mock())
        for token in ("", "contains space", "line\nbreak"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                directory_authorization({"directory_bearer_token": token}, None)

    @unittest.skipUnless(os.environ.get("CF_TEST_ACL_LIBRARY") and
                         os.environ.get("CF_TEST_REDIS_PORT"),
                         "requires compiled C ACL core and isolated Redis")
    def test_postfork_deployment_builds_complete_runtime_from_primitives(self):
        configured = self.configured()
        value = {
            "database": {"host": os.environ.get("CF_TEST_DB_HOST", "mysql"),
                "port": int(os.environ.get("CF_TEST_DB_PORT", "3306")),
                "user": "root", "name": "cloudfile", "password": ""},
            "redis": {"host": os.environ.get("CF_TEST_REDIS_HOST", "redis"),
                "port": int(os.environ["CF_TEST_REDIS_PORT"]), "password": ""},
            "provider": "etech", "native_schema": "ccnet_db", "identity_schema": "seahub_db",
            "directory_url": "https://directory.example.invalid/context/v2",
            "directory_bearer_token": "directory-token", "attribute_allowlist": [],
            "core_library": os.environ["CF_TEST_ACL_LIBRARY"], "cloud_mode": False,
            **configured,
        }
        deployment = configure_policy(value, directory_authorization=None,
                                      authorization_enabled=True)
        try:
            self.assertIs(deployment.service_refresh_factory.verifier,
                          deployment.delegation_issue_factory.verifier)
            self.assertIs(deployment.factory.resources.redis,
                          deployment.service_refresh_factory.verifier.revocations.redis)
        finally:
            deployment.close()


if __name__ == "__main__":
    unittest.main()
