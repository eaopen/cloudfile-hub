"""Export adapter contracts; mocks are not native authorization evidence."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from contextlib import nullcontext

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.authorized_export import AuthorizedAuditCSV
from cloudfile_extensions.events.authorized_query import AuthorizedAuditQuery


class AuthorizedAuditExportTests(unittest.TestCase):
    def setUp(self):
        self.repo = "11111111-1111-4111-8111-111111111111"
        self.query = Mock(spec=AuthorizedAuditQuery)
        self.query.authority = SimpleNamespace(actor="employee")
        self.query.export_epoch.return_value = "epoch-1"
        self.query.export_scope.side_effect = lambda repo: nullcontext()
        self.query.export_page.return_value = {"items": [], "next_cursor": None}
        self.query.export_upper_bound.return_value = 42
        self.exporter = AuthorizedAuditCSV(self.query, repo_id=self.repo)

    def test_cutoff_and_pages_use_actual_query_consumer(self):
        self.assertEqual(self.exporter.reader.upper_bound(), 42)
        list(self.exporter.generate(actor="employee", repo_id=self.repo,
            start="2026-09-01T00:00:00Z", end="2026-09-02T00:00:00Z", upper_bound=42))
        self.query.export_upper_bound.assert_called_once_with(self.repo)
        self.query.export_page.assert_called_once_with(dict(repo_id=self.repo,
            start="2026-09-01T00:00:00Z", end="2026-09-02T00:00:00Z"),
            limit=200, cursor=None, upper_bound=42, expected_epoch="epoch-1")

    def test_other_repository_never_reaches_page_consumer(self):
        with self.assertRaises(ContractError):
            list(self.exporter.generate(actor="employee",
                repo_id="22222222-2222-4222-8222-222222222222", upper_bound=42))
        self.query.export_page.assert_not_called()

    def test_revocation_prevents_csv_output(self):
        self.query.export_epoch.side_effect = ContractError("ACCESS_DENIED", "Denied", 403)
        with self.assertRaises(ContractError):
            next(self.exporter.generate(actor="employee", repo_id=self.repo, upper_bound=42))
        self.query.export_page.assert_not_called()

    def test_epoch_change_after_last_page_prevents_completion(self):
        self.query.export_epoch.side_effect = ["epoch-1", "epoch-2"]
        with self.assertRaises(ContractError) as caught:
            list(self.exporter.generate(actor="employee", repo_id=self.repo, upper_bound=42))
        self.assertEqual(caught.exception.code, "SUBJECT_UNAVAILABLE")
        self.assertFalse(self.exporter.generating)

    def test_publication_recheck_keeps_generated_epoch(self):
        list(self.exporter.generate(actor="employee", repo_id=self.repo, upper_bound=42))
        self.query.export_epoch.return_value = "epoch-2"
        with self.assertRaises(ContractError):
            self.exporter.authorize("employee", self.repo)
