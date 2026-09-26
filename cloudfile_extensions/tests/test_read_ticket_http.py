"""HTTP input boundaries only; not native issuance or transfer evidence."""
import json
import unittest

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.identity.read_ticket_http import OIDCReadTicketView


class ReadTicketHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.view = OIDCReadTicketView.as_view()
        self.body = dict(reference=dict(repo_id="11111111-1111-1111-1111-111111111111",
            path="/file", kind="file"))

    def request(self, body=None, **headers):
        token = _get_new_csrf_string()
        options = dict(HTTP_COOKIE="csrftoken=" + token, HTTP_X_CSRFTOKEN=token,
            HTTP_ORIGIN="https://testserver")
        options.update(headers)
        return self.requests.post("/tickets/", data=json.dumps(self.body) if body is None else body,
            content_type="application/json", secure=True, **options)

    def test_method_tls_and_csrf(self):
        self.assertEqual(self.view(self.requests.get("/tickets/", secure=True)).status_code, 405)
        self.assertEqual(self.view(self.requests.post("/tickets/")).status_code, 401)
        request = self.requests.post("/tickets/", data="{}", content_type="application/json", secure=True)
        self.assertEqual(self.view(request).status_code, 403)

    def test_no_machine_credentials_or_compression(self):
        for headers in (dict(HTTP_AUTHORIZATION="Bearer fixture"), dict(HTTP_CONTENT_ENCODING="gzip")):
            with self.subTest(headers=headers):
                self.assertEqual(self.view(self.request(**headers)).status_code, 400)

    def test_invalid_payload_precedes_runtime_allocation(self):
        for body in ('{"reference":{},"reference":{}}', '{}',
                json.dumps(dict(self.body, userId="other")),
                json.dumps(dict(self.body, operation="upload")),
                json.dumps(dict(reference=dict(self.body["reference"], path="/../secret")))):
            with self.subTest(body=body):
                self.assertEqual(self.view(self.request(body)).status_code, 400)

    def test_oversized_body(self):
        self.assertEqual(self.view(self.request(" " * 16385)).status_code, 413)

    def test_missing_runtime_never_returns_ticket_and_disables_caching(self):
        response = self.view(self.request())
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("ticket", json.loads(response.content))
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertTrue(response["X-Request-ID"])
