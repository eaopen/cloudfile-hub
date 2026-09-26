"""Target response boundaries; mocks are not native authorization evidence."""
import unittest
from unittest.mock import patch

from cloudfile_extensions.identity.ticket_transport import resolve_and_issue_native_ticket


class TicketResolutionTests(unittest.TestCase):
    def resolve(self):
        return resolve_and_issue_native_ticket("repo", "/file", "download", "user", "{}")

    def test_invalid_or_ambiguous_head_never_resolves_file(self):
        for repo in (None, [], {}, {"head_cmmt_id": None}, {"head_cmmt_id": 1},
                {"head_cmmt_id": "a" * 39}, {"head_cmmt_id": "A" * 40},
                {"head_cmmt_id": "a" * 40, "head-cmmt-id": "a" * 40}):
            with self.subTest(repo=repo), patch(
                    "cloudfile_extensions.identity.ticket_transport._call", return_value=repo) as calls:
                with self.assertRaises(ValueError):
                    self.resolve()
                self.assertEqual(calls.call_count, 1)

    def test_invalid_file_object_never_issues_ticket(self):
        for obj in (None, {}, 1, True, "", "a" * 39, "A" * 40, "a" * 40 + "\x00"):
            with self.subTest(obj=obj), patch(
                    "cloudfile_extensions.identity.ticket_transport._call",
                    side_effect=[{"head_cmmt_id": "a" * 40}, obj]) as calls:
                with self.assertRaises(ValueError):
                    self.resolve()
                self.assertEqual(calls.call_count, 2)

    def test_invalid_ticket_response_rejected(self):
        for ticket in (None, {}, 1, "", "not-a-ticket", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"):
            with self.subTest(ticket=ticket), patch(
                    "cloudfile_extensions.identity.ticket_transport._call", side_effect=[
                        {"head_cmmt_id": "a" * 40}, "b" * 40, ticket]):
                with self.assertRaises(ValueError):
                    self.resolve()

    def test_hyphenated_native_property_and_shared_deadline(self):
        ticket = "11111111-1111-1111-1111-111111111111"
        with patch("cloudfile_extensions.identity.ticket_transport._call", side_effect=[
                {"head-cmmt-id": "a" * 40}, "b" * 40, ticket]) as calls:
            self.assertEqual(self.resolve(), ticket)
        self.assertEqual(len({call.args[2] for call in calls.call_args_list}), 1)
        self.assertEqual(calls.call_args_list[2].args[1],
            ("repo", "/file", "a" * 40, "b" * 40, "download", "user", "{}"))
