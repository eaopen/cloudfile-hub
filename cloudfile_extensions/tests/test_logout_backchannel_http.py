"""HTTP intake boundary regressions, not native logout integration evidence."""
from contextlib import contextmanager
import unittest
from unittest.mock import Mock

from django.test import RequestFactory

from cloudfile_extensions.identity.logout_backchannel_http import BackchannelLogoutView
from cloudfile_extensions.identity.logout_resources import LogoutResources
from cloudfile_extensions.identity.logout_jobs import BackchannelJobs
from cloudfile_extensions.common.errors import ContractError


class BackchannelHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.resources = Mock(spec=LogoutResources)
        self.jobs = Mock(spec=BackchannelJobs)
        @contextmanager
        def intake():
            yield self.jobs
        self.resources.intake.side_effect = intake
        self.view = BackchannelLogoutView.as_view(resources=self.resources)

    def request(self, data=b"logout_token=fixture.jwt.signature", **headers):
        return self.requests.post("/logout/backchannel/", data=data,
            content_type="application/x-www-form-urlencoded", secure=True, **headers)

    def test_acknowledges_without_exposing_job_or_claiming_completion(self):
        response = self.view(self.request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")
        self.jobs.submit.assert_called_once_with("fixture.jwt.signature")
        self.assertIn("no-store", response["Cache-Control"])

    def test_rejects_invalid_form_before_assembly(self):
        for body in (b"", b"logout_token=", b"logout_token=a&logout_token=b",
                b"logout_token=a&extra=b", b"wrong=a", b"logout_token", b"x" * 65537):
            with self.subTest(body_size=len(body)):
                self.assertEqual(self.view(self.request(body)).status_code, 400)
        self.resources.intake.assert_not_called()

    def test_rejects_browser_and_alternate_credentials(self):
        for headers in ({"HTTP_COOKIE": "sessionid=fixture"},
                {"HTTP_AUTHORIZATION": "Bearer fixture"}, {"HTTP_CONTENT_ENCODING": "gzip"}):
            self.assertEqual(self.view(self.request(**headers)).status_code, 400)
        self.resources.intake.assert_not_called()

    def test_signature_error_does_not_acknowledge(self):
        self.jobs.submit.side_effect = ContractError("AUTHENTICATION_REQUIRED", "Invalid notification", 401)
        self.assertEqual(self.view(self.request()).status_code, 401)

    def test_resource_exit_failure_returns_retryable_failure(self):
        @contextmanager
        def failing():
            yield self.jobs
            raise RuntimeError("private transport details")
        self.resources.intake.side_effect = failing
        response = self.view(self.request())
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"private", response.content)
