"""Local logout input boundaries only; not native session deletion evidence."""
import unittest
from unittest.mock import Mock, patch

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.identity.browser_binding import BINDING_COOKIE
from cloudfile_extensions.identity.logout_http import LocalLogoutView
from cloudfile_extensions.identity.resources import LoginResources
from cloudfile_extensions.common.errors import ContractError


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
        # Instance-owned collaborators are established by LoginResources.__init__
        # and therefore are not present on the class used as the Mock spec.
        self.resources.resources = Mock()
        self.resources.prefix = "cf:"
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

    def test_sql_failure_still_clears_browser_binding_and_final_cookies(self):
        cookie = BINDING_COOKIE + "=" + "b" * 43
        with patch("cloudfile_extensions.identity.logout_http.OIDCSessionAuthority") as authority, patch(
                "cloudfile_extensions.identity.logout_http.BrowserLoginBindings") as registry:
            authority.return_value.terminate.side_effect = ContractError(
                "IDENTITY_UNAVAILABLE", "fixture SQL failure", 503)
            response = self.view(self.request(csrf=True, cookie=cookie))
        self.assertEqual(response.status_code, 503)
        registry.return_value.clear.assert_called_once()
        self.assertEqual(response.cookies[BINDING_COOKIE]["max-age"], 0)
        self.assertEqual(response.cookies["seahub_auth"]["max-age"], 0)

    def test_registry_failure_retains_error_cookie_expiry(self):
        cookie = BINDING_COOKIE + "=" + "b" * 43
        with patch("cloudfile_extensions.identity.logout_http.OIDCSessionAuthority"), patch(
                "cloudfile_extensions.identity.logout_http.BrowserLoginBindings") as registry:
            registry.return_value.clear.side_effect = RuntimeError("fixture Redis failure")
            response = self.view(self.request(csrf=True, cookie=cookie))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.cookies[BINDING_COOKIE]["max-age"], 0)
        self.assertEqual(response.cookies["seahub_auth"]["max-age"], 0)
