"""HTTP adapter/CSRF boundaries; service output is an explicit fixture."""
from contextlib import contextmanager
import json
import unittest
from unittest.mock import Mock
from uuid import uuid4

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.identity.pending import PendingLoginStatus
from cloudfile_extensions.identity.pending_http import PendingStatusView


class PendingHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.service = Mock(spec=PendingLoginStatus)
        self.service.proofs = Mock()
        self.value = dict(job_id=str(uuid4()), status="queued", retryable=False)
        self.service.status.return_value = self.value
        @contextmanager
        def factory(request_id):
            yield self.service
        self.view = PendingStatusView.as_view(service_factory=factory)

    def request(self, method="get", path="/pending/", secure=True):
        request = getattr(self.requests, method)(path, data="" if method == "post" else None,
            content_type="application/octet-stream", secure=secure, HTTP_AUTHORIZATION="CloudFilePending " + "a" * 43)
        request.COOKIES[PendingStatusView.binding_cookie] = "browser-binding-" * 3
        return request

    def test_status_is_fixed_dto_and_never_cached(self):
        response = self.view(self.request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), self.value)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Vary"], "Cookie, Authorization")

    def test_https_binding_header_and_url_boundaries(self):
        request = self.request()
        request.COOKIES.clear()
        self.assertEqual(self.view(request).status_code, 401)
        self.assertEqual(self.view(self.request(secure=False)).status_code, 401)
        self.assertEqual(self.view(self.request(path="/pending/?token=private")).status_code, 400)
        request = self.request()
        request.META["HTTP_AUTHORIZATION"] = "Bearer private"
        self.assertEqual(self.view(request).status_code, 401)
        self.service.status.assert_not_called()

    def test_revoke_requires_csrf_and_verified_browser_proof(self):
        self.assertEqual(self.view(self.request(method="post")).status_code, 403)
        self.service.proofs.revoke.assert_not_called()
        request = self.request(method="post")
        csrf = _get_new_csrf_string()
        request.COOKIES["csrftoken"] = csrf
        request.META.update(HTTP_X_CSRFTOKEN=csrf, HTTP_ORIGIN="https://testserver")
        response = self.view(request)
        self.assertEqual(response.status_code, 200)
        self.service.proofs.read.assert_called_once_with("a" * 43, "browser-binding-" * 3)
        self.service.proofs.revoke.assert_called_once_with("a" * 43)

    def test_unconfigured_or_faulty_service_fails_without_private_output(self):
        self.assertEqual(PendingStatusView.as_view()(self.request()).status_code, 503)
        self.service.status.side_effect = RuntimeError("private credential")
        response = self.view(self.request())
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"private credential", response.content)
        self.service.status.side_effect = None
        self.service.status.return_value = {**self.value, "request": "private"}
        self.assertEqual(self.view(self.request()).status_code, 503)
