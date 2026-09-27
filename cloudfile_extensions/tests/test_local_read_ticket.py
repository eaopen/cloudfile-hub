"""Adapter protocol tests; actual native transfer integration remains separate."""
import unittest
from unittest.mock import Mock, patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.ticket_transport import resolve_and_issue_native_ticket
from cloudfile_extensions.local_edit.agent_runtime import AgentClaimRuntime
from cloudfile_extensions.local_edit.read_ticket import AgentReadTicketIssuer
from cloudfile_extensions.local_edit.session_service import NativeLocalReadConditions


class LocalReadTicketTests(unittest.TestCase):
    def test_changed_object_does_not_issue(self):
        with patch("cloudfile_extensions.identity.ticket_transport._call", side_effect=[
                {"head_cmmt_id": "a" * 40}, "b" * 40]) as calls:
            with self.assertRaises(ValueError):
                resolve_and_issue_native_ticket("repo", "/file", "download", "native", "{}",
                    expected_object_id="c" * 40)
        self.assertEqual(calls.call_count, 2)

    def test_internal_conditions_only_and_fixed_download(self):
        runtime = object.__new__(AgentClaimRuntime)
        runtime.prepare_native_read = Mock(return_value=NativeLocalReadConditions(
            "native", "private-conditions", "repo", "/file", "a" * 40))
        issuer = AgentReadTicketIssuer(runtime)
        with patch("cloudfile_extensions.local_edit.read_ticket.resolve_and_issue_native_ticket",
                return_value="ticket") as issue:
            self.assertEqual(issuer.issue({"proof": "value"}, "request"),
                dict(ticket="ticket", expires_in=60,
                    transfer=dict(path="/seafhttp/cloudfile/read", method="GET",
                        authorization="Bearer", redirects=False, resume=False),
                    file=dict(extension="", local_open_type="", mode="view", base_version="a" * 40)))
        issue.assert_called_once_with("repo", "/file", "download", "native",
            "private-conditions", expected_object_id="a" * 40)

    def test_rpc_failure_is_safe_and_never_retried(self):
        runtime = object.__new__(AgentClaimRuntime)
        runtime.prepare_native_read = Mock(return_value=NativeLocalReadConditions(
            "native", "secret", "repo", "/file", "a" * 40))
        with patch("cloudfile_extensions.local_edit.read_ticket.resolve_and_issue_native_ticket",
                side_effect=TimeoutError("secret")) as issue:
            with self.assertRaises(ContractError) as error:
                AgentReadTicketIssuer(runtime).issue({}, "request")
        self.assertEqual(issue.call_count, 1)
        self.assertNotIn("secret", str(error.exception))
