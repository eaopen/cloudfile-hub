"""Post-fork delegation issuance ownership and route proxy coverage."""

from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cloudfile_extensions.authorization.host import PolicyHost
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity import delegated_read_gunicorn, delegation_gunicorn


class DelegationHostTests(unittest.TestCase):
    def host(self, factory):
        deployment = SimpleNamespace(delegation_issue_factory=factory,
            delegated_read_factory=factory, close=Mock())
        with patch("cloudfile_extensions.authorization.host.configure_policy", return_value=deployment):
            return PolicyHost({}, directory_authorization=Mock()), deployment

    def test_issuance_scope_participates_in_host_drain(self):
        @contextmanager
        def factory(request, request_id, user_id):
            yield (request, request_id, user_id)

        host, deployment = self.host(factory)
        with host.delegation_issue_service("request", "request-id", "business-user") as issuer:
            self.assertEqual(issuer, ("request", "request-id", "business-user"))
            self.assertEqual(host.active, 1)
            self.assertFalse(host.drain())
            with self.assertRaises(ContractError):
                host.close()
        self.assertEqual(host.active, 0)
        host.close()
        deployment.close.assert_called_once_with()

    def test_missing_factory_fails_closed_and_releases_scope(self):
        host, _ = self.host(None)
        with self.assertRaises(ContractError) as raised:
            with host.delegation_issue_service("request", "request-id", "business-user"):
                self.fail("missing issuance factory accepted request")
        self.assertEqual(raised.exception.code, "POLICY_UNAVAILABLE")
        self.assertEqual(host.active, 0)

    def test_url_proxy_resolves_only_during_request(self):
        scope = Mock()
        with patch.object(delegation_gunicorn.policy_host,
                          "delegation_issue_service", return_value=scope) as service:
            result = delegation_gunicorn.delegation_issue_factory(
                "request", "request-id", "business-user")
        self.assertIs(result, scope)
        service.assert_called_once_with("request", "request-id", "business-user")

    def test_delegated_read_scope_participates_in_host_drain(self):
        @contextmanager
        def factory(request, request_id):
            yield (request, request_id)

        host, _ = self.host(factory)
        with host.delegated_read_service("request", "request-id") as issuer:
            self.assertEqual(issuer, ("request", "request-id"))
            self.assertEqual(host.active, 1)
            self.assertFalse(host.drain())
        host.close()

    def test_delegated_read_url_proxy_resolves_only_during_request(self):
        scope = Mock()
        with patch.object(delegated_read_gunicorn.policy_host,
                          "delegated_read_service", return_value=scope) as service:
            result = delegated_read_gunicorn.delegated_read_factory("request", "request-id")
        self.assertIs(result, scope)
        service.assert_called_once_with("request", "request-id")


if __name__ == "__main__":
    unittest.main()
