"""HTTP input/fail-closed and exact audit shapes, not actual resource authority."""
import unittest
from uuid import uuid4

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.events.outbox import normalize_event, projection_required
from cloudfile_extensions.local_edit.session_http import LocalSessionView, local_session_routes


class LocalSessionHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def post(self, body="{}", **headers):
        csrf = _get_new_csrf_string()
        values = dict(HTTP_COOKIE="csrftoken=" + csrf, HTTP_X_CSRFTOKEN=csrf, HTTP_ORIGIN="https://testserver")
        values.update(headers)
        return RequestFactory().post("/local/", data=body, content_type="application/json", secure=True, **values)

    def test_https_csrf_and_no_unassembled_success(self):
        view = LocalSessionView.as_view()
        self.assertEqual(view(RequestFactory().get("/local/", secure=True)).status_code, 405)
        self.assertEqual(view(RequestFactory().post("/local/")).status_code, 401)
        self.assertEqual(view(RequestFactory().post("/local/", data="{}", content_type="application/json", secure=True)).status_code, 403)
        response = view(self.post())
        self.assertEqual(response.status_code, 503)
        self.assertIn("no-store", response["Cache-Control"])

    def test_no_native_publish_operation_or_dynamic_factory(self):
        self.assertEqual(LocalSessionView.as_view(operation="commit")(self.post()).status_code, 400)
        with self.assertRaises(ValueError):
            local_session_routes(service_factory=lambda *_: None)
        for body in ('{"ticket":1,"ticket":2}', '{"ticket":NaN}', '{} {}'):
            self.assertEqual(LocalSessionView.as_view()(self.post(body)).status_code, 400)
        self.assertEqual(LocalSessionView.as_view()(self.post(" " * 16385)).status_code, 413)
        self.assertEqual(LocalSessionView.as_view()(self.post(HTTP_CONTENT_ENCODING="gzip")).status_code, 400)

    def test_session_metadata_audit_is_not_file_commit_projection(self):
        fact = dict(event_id=str(uuid4()), request_id="local-request", occurred_at="2026-09-27T00:00:00Z",
            actor_user_id="user-1", actor_kind="user", source="hub", action="local.session.created",
            result="succeeded", session_id=str(uuid4()), device_id=str(uuid4()), repo_id=str(uuid4()),
            path="/drawing.prt", resource_kind="file", resource_uid=str(uuid4()), revision="1", content_version="a" * 40)
        self.assertFalse(projection_required(normalize_event(fact)))
        self.assertTrue(projection_required(normalize_event({**fact, "action": "local.session.committed"})))
        self.assertTrue(projection_required(normalize_event({**fact, "target_path": "/moved.prt"})))
