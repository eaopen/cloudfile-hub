"""Device HTTP and immutable audit disposition, not native login integration."""
import unittest
from uuid import uuid4

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import normalize_event, projection_required
from cloudfile_extensions.local_edit.device_http import DeviceManagementView, device_routes


class DeviceHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def post(self, body="{}", **headers):
        csrf = _get_new_csrf_string()
        values = dict(HTTP_COOKIE="csrftoken=" + csrf, HTTP_X_CSRFTOKEN=csrf,
            HTTP_ORIGIN="https://testserver")
        values.update(headers)
        return RequestFactory().post("/devices/", data=body, content_type="application/json", secure=True, **values)

    def test_post_tls_csrf_and_missing_runtime(self):
        view = DeviceManagementView.as_view()
        self.assertEqual(view(RequestFactory().get("/devices/", secure=True)).status_code, 405)
        self.assertEqual(view(RequestFactory().post("/devices/")).status_code, 401)
        self.assertEqual(view(RequestFactory().post("/devices/", data="{}", content_type="application/json", secure=True)).status_code, 403)
        response = view(self.post())
        self.assertEqual(response.status_code, 503)
        self.assertIn("no-store", response["Cache-Control"])

    def test_strict_json_compression_and_no_edit_operation(self):
        view = DeviceManagementView.as_view()
        for body in ('{"x":1,"x":2}', '{"x":NaN}', '{} {}'):
            self.assertEqual(view(self.post(body)).status_code, 400)
        self.assertEqual(view(self.post(" " * 16385)).status_code, 413)
        self.assertEqual(view(self.post(HTTP_CONTENT_ENCODING="gzip")).status_code, 400)
        self.assertEqual(DeviceManagementView.as_view(operation="commit")(self.post()).status_code, 400)
        with self.assertRaises(ValueError):
            device_routes(service_factory=lambda *_: None)

    def test_device_facts_are_audit_only_without_key_or_nonce(self):
        fact = dict(event_id=str(uuid4()), request_id="device-request", occurred_at="2026-09-27T00:00:00Z",
            actor_user_id="user-1", actor_kind="user", source="hub", action="device.paired",
            result="succeeded", device_id=str(uuid4()), revision="2")
        self.assertFalse(projection_required(normalize_event(fact)))
        with self.assertRaises(ContractError):
            normalize_event({**fact, "nonce": "private"})
        with self.assertRaises(ContractError):
            normalize_event({**fact, "device_id": "invalid"})
        # Never broadly skip future session/commit/file facts just for containing
        # a device UUID: unknown or resource-bearing events still need projection.
        self.assertTrue(projection_required({**fact, "action": "device.unknown"}))
        self.assertTrue(projection_required({**fact, "resource_uid": str(uuid4())}))
