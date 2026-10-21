"""A marked permission-runtime failure must not be published as a 403 denial."""
import json
import unittest
from uuid import UUID

from django.conf import settings

if not settings.configured:
    settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"],
        DEFAULT_CHARSET="utf-8")
import django
django.setup()

from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory

from cloudfile_extensions.permission_middleware import (
    CloudFilePermissionMiddleware, mark_permission_unavailable,
    permission_unavailable,
)


class PermissionMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self.requests = RequestFactory()

    def response_for(self, request, status=403):
        def get_response(request):
            return JsonResponse({"error_msg": "Permission denied."}, status=status)
        return CloudFilePermissionMiddleware(get_response)(request)

    def test_marked_permission_failure_becomes_503(self):
        request = self.requests.get("/api/v2.1/repos/")
        mark_permission_unavailable(request)
        self.assertIs(permission_unavailable(request), True)
        response = self.response_for(request)
        self.assertEqual(response.status_code, 503)
        body = json.loads(response.content)
        self.assertEqual(body["code"], "POLICY_UNAVAILABLE")
        self.assertNotIn("Permission denied", body["message"])
        UUID(body["request_id"])
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["X-Request-ID"], body["request_id"])

    def test_unmarked_denials_and_other_statuses_are_untouched(self):
        plain = self.requests.get("/api/v2.1/repos/")
        response = self.response_for(plain)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content), {"error_msg": "Permission denied."})

        marked = self.requests.get("/api/v2.1/repos/")
        mark_permission_unavailable(marked)
        for status in (200, 404, 500):
            with self.subTest(status=status):
                self.assertEqual(self.response_for(marked, status=status).status_code, status)

    def test_marking_never_raises_on_a_hostile_request(self):
        class Hostile:
            def __setattr__(self, name, value):
                raise RuntimeError("no attributes")
        request = Hostile()
        mark_permission_unavailable(request)
        self.assertIs(permission_unavailable(request), False)


if __name__ == "__main__":
    unittest.main()
