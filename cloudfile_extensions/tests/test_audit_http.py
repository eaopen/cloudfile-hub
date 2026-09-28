"""The public audit query is bounded and mounted only by explicit deployment choice."""
from contextlib import contextmanager
import json
import unittest
from unittest.mock import Mock, patch

from django.test import RequestFactory, override_settings
from django.urls import resolve

from cloudfile_extensions.authorization import gunicorn
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.authorized_query import AuthorizedAuditQuery
from cloudfile_extensions.events.http import AuditEventsView


class AuditHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"],
                DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.service = Mock(spec=AuthorizedAuditQuery)
        self.service.events.return_value = {"items": [], "next_cursor": None}
        self.closed = False

        @contextmanager
        def factory(request, request_id):
            try:
                yield self.service
            finally:
                self.closed = True

        self.view = AuditEventsView.as_view(service_factory=factory)
        self.query = dict(repo_id="11111111-1111-4111-8111-111111111111",
            start="2026-09-01T00:00:00Z", end="2026-09-02T00:00:00Z")

    def request(self, **changes):
        return self.requests.get("/audit/v1/events/", data={**self.query, **changes}, secure=True)

    def test_query_route_uses_worker_owned_service(self):
        target = resolve("/v1/events/", urlconf="cloudfile_extensions.events.urls")
        self.assertIs(target.func.view_class, AuditEventsView)
        self.assertIs(target.func.view_initkwargs["service_factory"], gunicorn.audit_service)

    def test_bounded_query_and_cursor_are_forwarded(self):
        response = self.view(self.request(limit="25", cursor="signed-cursor"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"items": [], "next_cursor": None})
        self.service.events.assert_called_once_with(self.query, limit=25, cursor="signed-cursor")
        self.assertTrue(self.closed)
        self.assertIn("no-store", response["Cache-Control"])

    def test_invalid_input_does_not_allocate_audit_scope(self):
        for request in (self.requests.get("/audit/v1/events/?repo_id=x&repo_id=y", secure=True),
                self.request(limit="201"), self.request(actor="forged"),
                self.requests.get("/audit/v1/events/", data=self.query, secure=False)):
            self.assertIn(self.view(request).status_code, (400, 401))
        self.service.events.assert_not_called()

    def test_revocation_and_failure_are_not_empty_logs(self):
        self.service.events.side_effect = ContractError("ACCESS_DENIED", "Denied", 403)
        self.assertEqual(self.view(self.request()).status_code, 403)
        self.service.events.side_effect = RuntimeError("private database password")
        response = self.view(self.request())
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"private database password", response.content)

    def test_enabled_route_requires_trusted_worker_configuration(self):
        with override_settings(CLOUDFILE_AUDIT_QUERY_ENABLED=True,
                CLOUDFILE_OIDC_ENABLED=False, CLOUDFILE_AUTHORIZATION_ENABLED=False), \
                patch.object(gunicorn, "_host", None):
            with self.assertRaises(RuntimeError):
                gunicorn.post_worker_init(Mock())
