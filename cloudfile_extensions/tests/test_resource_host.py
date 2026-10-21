"""Owned resource host coverage; execution deferred until feature completion."""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cloudfile_extensions.authorization.host import PolicyHost
from cloudfile_extensions.common.errors import ContractError


class ResourceHostTest(unittest.TestCase):
    def test_resource_scope_participates_in_drain_and_pool_ownership(self):
        @contextmanager
        def factory(request, request_id):
            yield "resource"
        deployment = SimpleNamespace(factory=Mock(), resource_factory=factory, close=Mock())
        with patch("cloudfile_extensions.authorization.host.configure_policy", return_value=deployment):
            host = PolicyHost({}, directory_authorization=Mock())
        with host.resource_service(object(), "request") as service:
            self.assertEqual(service, "resource")
            self.assertEqual(host.active, 1)
            self.assertFalse(host.drain())
            with self.assertRaises(ContractError):
                host.close()
            deployment.close.assert_not_called()
        self.assertEqual(host.active, 0)
        host.close()
        deployment.close.assert_called_once_with()
        with self.assertRaises(ContractError):
            with host.resource_service(object(), "request"):
                self.fail("closed host accepted resource request")

    def test_missing_resource_configuration_releases_active_scope(self):
        deployment = SimpleNamespace(factory=Mock(), resource_factory=None, close=Mock())
        with patch("cloudfile_extensions.authorization.host.configure_policy", return_value=deployment):
            host = PolicyHost({}, directory_authorization=Mock())
        with self.assertRaises(ContractError) as raised:
            with host.resource_service(object(), "request"):
                self.fail("missing factory accepted request")
        self.assertEqual(raised.exception.code, "RESOURCE_UNAVAILABLE")
        self.assertEqual(host.active, 0)
        deployment.factory.assert_not_called()
