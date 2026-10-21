import json
from unittest import TestCase

from django.test import RequestFactory

from cloudfile_extensions.events.read_reconciliation_http import ReadReconciliationView


class ReadReconciliationHTTPTest(TestCase):
    def request(self, body=None, **options):
        request = RequestFactory().post("/fixture", data=json.dumps(body or dict(repo_id="repo", start="start", end="end")),
            content_type="application/json", secure=True, **options)
        request._dont_enforce_csrf_checks = True
        return request

    def test_protocol_rejection_before_resource_allocation(self):
        for header in (dict(HTTP_AUTHORIZATION="Bearer machine"), dict(HTTP_AUTHORIZATION=""),
                dict(HTTP_CONTENT_ENCODING="gzip"), dict(QUERY_STRING="limit=10000")):
            self.assertEqual(ReadReconciliationView.as_view()(self.request(**header)).status_code, 400)

    def test_unknown_budget_subject_and_retention_fields_rejected(self):
        for field in ("actor", "userId", "limit", "cursor", "cutoff", "repair", "max_pages"):
            value = dict(repo_id="repo", start="start", end="end", **{field: "forged"})
            request = self.request(body=value)
            self.assertEqual(ReadReconciliationView.as_view()(request).status_code, 400)

    def test_missing_owned_runtime_does_not_enable_report(self):
        self.assertEqual(ReadReconciliationView.as_view()(self.request()).status_code, 503)
