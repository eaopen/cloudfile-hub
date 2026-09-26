"""Migration HTTPS/input boundaries, not actual library authorization proof."""
import unittest

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.migration.http import MigrationJobView
from cloudfile_extensions.migration.routes import migration_routes


class MigrationHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()

    def post(self, body="{}", **headers):
        csrf = _get_new_csrf_string()
        values = dict(HTTP_COOKIE="csrftoken=" + csrf, HTTP_X_CSRFTOKEN=csrf, HTTP_ORIGIN="https://testserver")
        values.update(headers)
        return self.requests.post("/migration/", data=body, content_type="application/json", secure=True, **values)

    def test_tls_csrf_and_method(self):
        view = MigrationJobView.as_view()
        self.assertEqual(view(self.requests.get("/migration/", secure=True)).status_code, 405)
        self.assertEqual(view(self.requests.post("/migration/")).status_code, 401)
        self.assertEqual(view(self.requests.post("/migration/", data="{}", content_type="application/json", secure=True)).status_code, 403)

    def test_submissions_require_idempotency_and_reject_compression(self):
        view = MigrationJobView.as_view(operation="stage")
        self.assertEqual(view(self.post()).status_code, 428)
        self.assertEqual(view(self.post(HTTP_IDEMPOTENCY_KEY="contains space")).status_code, 400)
        self.assertEqual(view(self.post(HTTP_IDEMPOTENCY_KEY="attempt-1", HTTP_CONTENT_ENCODING="gzip")).status_code, 400)
        self.assertEqual(view(self.post(HTTP_IDEMPOTENCY_KEY="attempt-1")).status_code, 503)

    def test_strict_json_and_budget(self):
        view = MigrationJobView.as_view()
        for body in ('{"job_id":1,"job_id":2}', '{"job_id":NaN}', '{} {}'):
            self.assertEqual(view(self.post(body)).status_code, 400)
        self.assertEqual(view(self.post(" " * 16385)).status_code, 413)

    def test_actual_import_cannot_be_selected_and_missing_runtime_is_not_success(self):
        self.assertEqual(MigrationJobView.as_view(operation="import")(self.post()).status_code, 400)
        response = MigrationJobView.as_view()(self.post())
        self.assertEqual(response.status_code, 503)
        self.assertIn("no-store", response["Cache-Control"])
        with self.assertRaises(ValueError):
            migration_routes(service_factory=lambda *_: None)
