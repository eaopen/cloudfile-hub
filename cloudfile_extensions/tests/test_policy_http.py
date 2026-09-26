"""HTTP contract fixtures, not actual session/native authority evidence."""
from contextlib import contextmanager
import json
import unittest
from unittest.mock import Mock
from uuid import uuid4

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.authorization.http import DirectoryPolicyView
from cloudfile_extensions.authorization.service import DirectoryPolicyService
from cloudfile_extensions.common.errors import ContractError


class PolicyHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.service = Mock(spec=DirectoryPolicyService)
        self.service.list.return_value = dict(items=[], next_after=None)
        self.service.create.return_value = dict(id=str(uuid4()))
        self.closed = False
        @contextmanager
        def factory(request, request_id):
            try:
                yield self.service
            finally:
                self.closed = True
        self.view = DirectoryPolicyView.as_view(service_factory=factory)
        self.ref = dict(repo_id=str(uuid4()), path="/a%20b+图", kind="dir")

    def write(self, data, *, csrf=True):
        request = self.requests.post("/policy/", data=data, content_type="application/json", secure=True,
            HTTP_IDEMPOTENCY_KEY="create")
        if csrf:
            token = _get_new_csrf_string()
            request.COOKIES["csrftoken"] = token
            request.META.update(HTTP_X_CSRFTOKEN=token, HTTP_ORIGIN="https://testserver")
        return request

    def test_query_decodes_only_once_and_response_is_not_cached(self):
        request = self.requests.get("/policy/", data=self.ref, secure=True)
        response = self.view(request)
        self.assertEqual(response.status_code, 200)
        self.service.list.assert_called_once_with("acl", dict(reference=self.ref), limit=50, after=None)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertTrue(self.closed)

    def test_csrf_duplicate_json_and_size_reject_before_service(self):
        self.assertEqual(self.view(self.write("{}", csrf=False)).status_code, 403)
        self.assertEqual(self.view(self.write('{"reference":{},"reference":{}}')).status_code, 400)
        self.assertEqual(self.view(self.write("x" * 16385)).status_code, 413)
        self.assertEqual(self.view(self.write('{"value":NaN}')).status_code, 400)
        self.service.create.assert_not_called()

    def test_duplicate_query_and_wrong_method_target(self):
        self.assertEqual(self.view(self.requests.get("/policy/?kind=dir&kind=file", secure=True)).status_code, 400)
        self.assertEqual(self.view(self.requests.get("/policy/", data=self.ref, secure=True), rule_id=str(uuid4())).status_code, 405)
        self.assertEqual(self.view(self.requests.get("/policy/", data=self.ref, secure=False)).status_code, 401)
        self.service.list.assert_not_called()

    def test_factory_absent_and_domain_errors_are_safe_and_release_scope(self):
        request = lambda: self.requests.get("/policy/", data=self.ref, secure=True)
        self.assertEqual(DirectoryPolicyView.as_view()(request()).status_code, 503)
        self.service.list.side_effect = ContractError("ACCESS_DENIED", "Denied", 403)
        self.assertEqual(self.view(request()).status_code, 403)
        self.assertTrue(self.closed)
        self.service.list.side_effect = RuntimeError("private password")
        response = self.view(request())
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"private password", response.content)

    def test_write_dispatch_and_header_key(self):
        body = dict(reference=self.ref, value={})
        self.assertEqual(self.view(self.write(json.dumps(body))).status_code, 200)
        self.service.create.assert_called_once_with("acl", body, idempotency_key="create")
