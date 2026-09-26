"""HTTP routing/authentication-mode regressions; not real authority evidence."""
from contextlib import contextmanager
import unittest
from unittest.mock import Mock

from django.middleware.csrf import CsrfViewMiddleware
from django.test import RequestFactory

from cloudfile_extensions.directory.refresh_http import (MachineUserRefreshView, UserRefreshView,
    MachineUserRefreshCancelView, UserRefreshCancelView)
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.refresh_management import UserRefreshManagement


class RefreshHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.service = Mock(spec=UserRefreshManagement)
        self.service.machine = True
        self.service.submit.return_value = ("11111111-1111-4111-8111-111111111111", True)
        self.job = "11111111-1111-4111-8111-111111111111"
        self.etag = '"cf-refresh:' + self.job + ':1"'
        self.service.status.return_value = (dict(status="queued"), self.etag)
        self.service.cancel.return_value = (dict(status="cancelled"), self.etag)
        self.closed = False
        @contextmanager
        def factory(request, request_id):
            try:
                yield self.service
            finally:
                self.closed = True
        self.machine = MachineUserRefreshView.as_view(service_factory=factory)
        self.session = UserRefreshView.as_view(service_factory=factory)
        self.cancel = MachineUserRefreshCancelView.as_view(service_factory=factory)
        self.session_cancel = UserRefreshCancelView.as_view(service_factory=factory)

    def cancel_request(self, condition=None, **headers):
        if condition is not None:
            headers["HTTP_IF_MATCH"] = condition
        return self.requests.post("/refreshes/" + self.job + "/cancel/", data=b"",
            content_type="application/octet-stream", secure=True,
            HTTP_AUTHORIZATION="Bearer fixture", **headers)

    def test_cancel_requires_exact_condition_before_business_effect(self):
        self.assertEqual(self.cancel(self.cancel_request(), job_id=self.job).status_code, 428)
        for condition in ("*", "W/" + self.etag, self.etag + ", " + self.etag):
            self.assertEqual(self.cancel(self.cancel_request(condition), job_id=self.job).status_code, 400)
        self.service.cancel.assert_not_called()

    def test_cancel_preserves_condition_and_current_authority_failure(self):
        response = self.cancel(self.cancel_request(self.etag), job_id=self.job)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["ETag"], self.etag)
        self.service.cancel.assert_called_once_with(self.job, expected_attempt=1, with_condition=True)
        self.service.cancel.side_effect = ContractError("PRECONDITION_FAILED", "Attempt changed", 412)
        response = self.cancel(self.cancel_request(self.etag), job_id=self.job)
        self.assertEqual(response.status_code, 412)
        self.assertIn("no-store", response["Cache-Control"])

    def test_cancel_session_csrf_and_machine_cookie_boundaries(self):
        self.assertEqual(self.session_cancel(self.cancel_request(self.etag), job_id=self.job).status_code, 403)
        self.assertEqual(self.cancel(self.cancel_request(self.etag, HTTP_COOKIE="sessionid=browser"), job_id=self.job).status_code, 400)
        self.service.cancel.assert_not_called()

    def request(self, **headers):
        return self.requests.post("/refreshes/", data="{}", content_type="application/json", secure=True,
            HTTP_IDEMPOTENCY_KEY="refresh-1", HTTP_AUTHORIZATION="Bearer fixture", **headers)

    def test_only_fixed_machine_view_is_csrf_exempt(self):
        self.assertTrue(getattr(self.machine, "csrf_exempt", False))
        self.assertFalse(getattr(self.session, "csrf_exempt", False))
        request = self.request()
        middleware = CsrfViewMiddleware(lambda _: None)
        middleware.process_request(request)
        self.assertIsNone(middleware.process_view(request, self.machine, (), {}))
        self.assertEqual(self.machine(request).status_code, 202)
        self.assertTrue(self.closed)

    def test_cookie_mixing_and_missing_bearer_reject_before_effects(self):
        self.assertEqual(self.machine(self.request(HTTP_COOKIE="sessionid=browser")).status_code, 400)
        request = self.request()
        del request.META["HTTP_AUTHORIZATION"]
        self.assertEqual(self.machine(request).status_code, 401)
        self.service.submit.assert_not_called()

    def test_authentication_mode_mismatch_fails_closed(self):
        self.service.machine = False
        response = self.machine(self.request())
        self.assertEqual(response.status_code, 503)
        self.service.submit.assert_not_called()

    def test_session_still_requires_csrf_and_machine_response_is_private(self):
        self.assertEqual(self.session(self.request()).status_code, 403)
        response = self.machine(self.request())
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("Authorization", response["Vary"])
