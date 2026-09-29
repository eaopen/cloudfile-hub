"""HTTPS/CSRF/body/route boundaries, not native authorization evidence."""
import json
import unittest

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.editing.http import EditingView
from cloudfile_extensions.editing.routes import editing_routes
from cloudfile_extensions.search.http import ResourceSearchView
from cloudfile_extensions.search.routes import search_routes


class SearchLockHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.search = ResourceSearchView.as_view()
        self.lock = EditingView.as_view(operation="file-lock")
        self.checkout = EditingView.as_view(operation="checkout")

    def post(self, body="{}", **headers):
        token = _get_new_csrf_string()
        options = dict(HTTP_COOKIE="csrftoken=" + token, HTTP_X_CSRFTOKEN=token,
            HTTP_ORIGIN="https://testserver")
        options.update(headers)
        return self.requests.post("/operation/", data=body, content_type="application/json",
            secure=True, **options)

    def test_method_tls_and_csrf_before_runtime(self):
        for view in (self.search, self.lock):
            self.assertEqual(view(self.requests.get("/operation/", secure=True)).status_code, 405)
            self.assertEqual(view(self.requests.post("/operation/")).status_code, 401)
            self.assertEqual(view(self.requests.post("/operation/", data="{}",
                content_type="application/json", secure=True)).status_code, 403)

    def test_lease_writes_require_bounded_idempotency_key(self):
        self.assertEqual(self.lock(self.post()).status_code, 428)
        for key in ("", "x" * 129, "contains space", "non-ascii-中"):
            self.assertEqual(self.lock(self.post(HTTP_IDEMPOTENCY_KEY=key)).status_code, 400)
        self.assertEqual(self.lock(self.post(HTTP_IDEMPOTENCY_KEY="attempt-1")).status_code, 503)

    def test_checkout_write_has_same_https_csrf_idempotency_boundary(self):
        self.assertEqual(self.checkout(self.requests.post("/operation/")).status_code, 401)
        self.assertEqual(self.checkout(self.post()).status_code, 428)
        self.assertEqual(self.checkout(self.post(HTTP_IDEMPOTENCY_KEY="attempt-1")).status_code, 503)

    def test_invalid_json_and_budget_fail_before_runtime(self):
        for view in (self.search, self.lock):
            for body in ('{"q":1,"q":2}', '{"q":NaN}', '{} {}'):
                self.assertEqual(view(self.post(body)).status_code, 400)
            self.assertEqual(view(self.post(" " * 16385)).status_code, 413)

    def test_missing_runtime_never_grants_or_caches(self):
        for view in (self.search, EditingView.as_view(operation="status")):
            response = view(self.post())
            self.assertEqual(response.status_code, 503)
            payload = json.loads(response.content)
            self.assertNotIn("items", payload)
            self.assertNotIn("token", payload)
            self.assertIn("no-store", response["Cache-Control"])
            self.assertEqual(response["Vary"], "Cookie, Authorization")
            self.assertTrue(response["X-Request-ID"])

    def test_generic_callable_cannot_replace_owned_factory(self):
        for assemble in (search_routes, editing_routes):
            for factory in (None, lambda *_: None):
                with self.assertRaises(ValueError):
                    assemble(service_factory=factory)
