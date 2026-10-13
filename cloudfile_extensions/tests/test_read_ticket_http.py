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
        self.assertEqual(self.view(self.requests.post("/tickets/")).status_code, 403)
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

    def test_library_and_directory_entries_choose_distinct_preflight(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        from django.test import override_settings
        from cloudfile_extensions.identity.read_ticket_http import OIDCReadTicketFactory
        from cloudfile_extensions.identity.resources import LoginResources
        for directory in (False, True):
            factory = OIDCReadTicketFactory(Mock(spec=LoginResources), directory_access=directory)
            issuer = Mock()
            issuer.issue.return_value = dict(ticket='fixture', expires_in=60)
            @contextmanager
            def scope(factory, request, request_id):
                yield issuer
            normal, scoped = Mock(), Mock()
            view = OIDCReadTicketView.as_view(service_factory=factory, directory_access=directory)
            with patch.object(OIDCReadTicketFactory, '__call__', scope), \
                    patch('cloudfile_extensions.identity.read_ticket_http.ContentReadAuthority', normal), \
                    patch('cloudfile_extensions.identity.read_ticket_http.native_scoped_authority', scoped), \
                    patch('cloudfile_extensions.identity.read_ticket_http.PolicyCore'), \
                    override_settings(CLOUDFILE_POLICY_CONFIG=dict(core_library='fixture', cloud_mode=False)):
                self.assertEqual(view(self.request()).status_code, 201)
            self.assertEqual(normal.call_count, int(not directory))
            self.assertEqual(scoped.call_count, int(directory))

    def test_client_cannot_select_directory_access_on_old_ticket_api(self):
        body = dict(self.body, directory_access=True)
        self.assertEqual(self.view(self.request(json.dumps(body))).status_code, 400)
