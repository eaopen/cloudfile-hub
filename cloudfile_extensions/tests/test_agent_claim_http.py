"""Cookie-free proof boundary only, not current-user/CE/native integration."""
import os
import unittest
from unittest.mock import patch

from django.test import RequestFactory

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.agent_http import AgentClaimView, agent_claim_routes
from cloudfile_extensions.local_edit.agent_runtime import AgentClaimRuntime


class AgentClaimHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def post(self, body="{}", **headers):
        return RequestFactory().post("/agent/claim/", data=body, content_type="application/json", secure=True, **headers)

    def test_cookie_authorization_compression_and_query_are_forbidden(self):
        view = AgentClaimView.as_view()
        for headers in ({"HTTP_COOKIE": ""}, {"HTTP_COOKIE": "sessionid=private"},
                {"HTTP_AUTHORIZATION": "Bearer private"}, {"HTTP_CONTENT_ENCODING": "identity"}):
            self.assertEqual(view(self.post(**headers)).status_code, 400)
        request = self.post(); request.META["QUERY_STRING"] = "ticket=private"
        self.assertEqual(view(request).status_code, 400)

    def test_method_tls_strict_json_budget_and_missing_runtime(self):
        view = AgentClaimView.as_view()
        self.assertEqual(view(RequestFactory().get("/agent/claim/", secure=True)).status_code, 405)
        self.assertEqual(view(RequestFactory().post("/agent/claim/")).status_code, 401)
        for body in ('{"userId":1,"userId":2}', '{"x":NaN}', '{} {}'):
            self.assertEqual(view(self.post(body)).status_code, 400)
        self.assertEqual(view(self.post(" " * 16385)).status_code, 413)
        response = view(self.post())
        self.assertEqual(response.status_code, 503)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(AgentClaimView.as_view(operation="download")(self.post()).status_code, 400)
        with self.assertRaises(ValueError):
            agent_claim_routes(runtime=lambda *_: True)

    def test_inherited_runtime_rejected_before_any_storage(self):
        runtime = object.__new__(AgentClaimRuntime)
        runtime.pid = os.getpid()
        with patch("cloudfile_extensions.local_edit.agent_runtime.os.getpid", return_value=runtime.pid + 1):
            with self.assertRaises(ContractError):
                runtime.challenge({}, "request")
