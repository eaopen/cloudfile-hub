"""Local logout input boundaries only; not native session deletion evidence."""
import unittest
from unittest.mock import Mock

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.identity.browser_binding import BINDING_COOKIE
from cloudfile_extensions.identity.logout_http import LocalLogoutView
from cloudfile_extensions.identity.resources import LoginResources


class LocalLogoutHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.resources = Mock(spec=LoginResources)
        self.view = LocalLogoutView.as_view(resources=self.resources)

    def request(self, *, csrf=False, cookie=None, **options):
        headers = {}
        if csrf:
            token = _get_new_csrf_string()
            headers.update(HTTP_COOKIE="csrftoken=" + token,
                HTTP_X_CSRFTOKEN=token, HTTP_ORIGIN="https://testserver")
        if cookie is not None:
            headers["HTTP_COOKIE"] = headers.get("HTTP_COOKIE", "") + "; " + cookie
        headers.update(options)
        return self.requests.post("/logout/", data=b"", content_type="application/octet-stream",
            secure=True, **headers)

    def test_post_https_csrf_required_before_effects(self):
        self.assertEqual(self.view(self.requests.get("/logout/", secure=True)).status_code, 405)
        self.assertEqual(self.view(self.requests.post("/logout/")).status_code, 401)
        self.assertEqual(self.view(self.request()).status_code, 403)
        self.resources.runtime.assert_not_called()

    def test_duplicate_browser_binding_rejected_after_csrf(self):
        cookie = BINDING_COOKIE + "=" + "b" * 43
        response = self.view(self.request(csrf=True, cookie=cookie + "; " + cookie))
        self.assertEqual(response.status_code, 401)
        self.assertIn("no-store", response["Cache-Control"])
        self.resources.runtime.assert_not_called()

    def test_no_body_query_or_machine_authorization(self):
        response = self.view(self.request(csrf=True, HTTP_AUTHORIZATION="Bearer fixture"))
        self.assertEqual(response.status_code, 400)
        response = self.view(self.requests.post("/logout/?next=https://other.invalid", secure=True))
        self.assertEqual(response.status_code, 400)
        response = self.view(self.requests.post("/logout/", data=b"x",
            content_type="application/octet-stream", secure=True))
        self.assertEqual(response.status_code, 400)
        self.resources.runtime.assert_not_called()
