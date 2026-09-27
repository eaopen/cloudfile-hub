"""Cookie-free delegated HTTP boundaries; no issuance/native evidence."""
import json
import unittest

from django.test import RequestFactory

from cloudfile_extensions.identity.delegated_read_http import DelegatedReadTicketView


class DelegatedReadHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.view = DelegatedReadTicketView.as_view()
        self.body = json.dumps(dict(reference=dict(repo_id="11111111-1111-1111-1111-111111111111",
            path="/file", kind="file")))

    def request(self, body=None, **headers):
        options = dict(HTTP_AUTHORIZATION="Bearer fixture")
        options.update(headers)
        request = self.requests.post("/delegated-read-tickets/", data=self.body if body is None else body,
            content_type="application/json", secure=True, **options)
        # RequestFactory synthesizes an empty Cookie header; the machine client
        # sends none. Keep explicit empty Cookie cases for the boundary test.
        if "HTTP_COOKIE" not in headers:
            request.META.pop("HTTP_COOKIE", None)
        return request

    def test_method_tls_and_bearer(self):
        self.assertEqual(self.view(self.requests.get("/tickets/", secure=True)).status_code, 405)
        self.assertEqual(self.view(self.requests.post("/tickets/")).status_code, 401)
        self.assertEqual(self.view(self.request(HTTP_AUTHORIZATION="")).status_code, 401)

    def test_any_browser_cookie_and_compression_rejected(self):
        for headers in (dict(HTTP_COOKIE=""), dict(HTTP_COOKIE="sessionid=fixture"),
                dict(HTTP_CONTENT_ENCODING="gzip")):
            with self.subTest(headers=headers):
                self.assertEqual(self.view(self.request(**headers)).status_code, 400)

    def test_subject_and_version_cannot_be_selected_by_request(self):
        for field in ("userId", "provider", "context_epoch", "head_id", "object_id"):
            body = json.loads(self.body)
            body[field] = "untrusted"
            with self.subTest(field=field):
                self.assertEqual(self.view(self.request(json.dumps(body))).status_code, 400)

    def test_duplicate_and_oversize_json(self):
        self.assertEqual(self.view(self.request('{"reference":{},"reference":{}}')).status_code, 400)
        self.assertEqual(self.view(self.request(" " * 16385)).status_code, 413)

    def test_no_runtime_is_safe_and_no_session_csrf_fallback(self):
        response = self.view(self.request())
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("ticket", json.loads(response.content))
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Vary"], "Authorization")
        self.assertTrue(response["X-Request-ID"])
