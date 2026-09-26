"""Middleware orchestration regressions; not actual DB/stream integration."""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from django.http import HttpResponse, StreamingHttpResponse
from django.contrib.sessions.middleware import SessionMiddleware

from cloudfile_extensions.identity.session_middleware import CloudFileSessionMiddleware
from cloudfile_extensions.common.errors import ContractError


class GuardedSessionMiddlewareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", DEFAULT_CHARSET="utf-8")

    def setUp(self):
        self.middleware = object.__new__(CloudFileSessionMiddleware)
        self.middleware.authority = Mock()
        self.middleware.oidc = Mock(return_value=True)
        self.request = SimpleNamespace(session=Mock())

    def test_actual_session_save_is_inside_guard(self):
        order = []
        @contextmanager
        def guard(request):
            order.append("enter")
            yield
            order.append("exit")
        self.middleware.authority.guard.side_effect = guard
        response = HttpResponse("private")
        def save(request, result):
            order.append("save")
            return result
        with patch.object(SessionMiddleware, "process_response", side_effect=save) as saved:
            self.assertIs(self.middleware.process_response(self.request, response), response)
            saved.assert_called_once_with(self.request, response)
        self.assertEqual(order, ["enter", "save", "exit"])

    def test_failed_final_guard_discards_original_response(self):
        @contextmanager
        def guard(request):
            yield
            raise ContractError("AUTHENTICATION_REQUIRED", "Invalidated", 401)
        self.middleware.authority.guard.side_effect = guard
        response = HttpResponse("private")
        replacement = HttpResponse(status=401)
        self.middleware.failure = Mock(return_value=replacement)
        with patch.object(SessionMiddleware, "process_response", return_value=response):
            self.assertIs(self.middleware.process_response(self.request, response), replacement)
        self.assertTrue(response.closed)
        self.middleware.failure.assert_called_once()

    def test_unguarded_stream_never_released_or_saved(self):
        response = StreamingHttpResponse(iter([b"private"]))
        replacement = HttpResponse(status=503)
        self.middleware.failure = Mock(return_value=replacement)
        with patch.object(SessionMiddleware, "process_response") as save:
            self.assertIs(self.middleware.process_response(self.request, response), replacement)
            save.assert_not_called()
        self.assertTrue(response.closed)
        self.middleware.authority.guard.assert_not_called()

    def test_non_oidc_preserves_native_session_behavior(self):
        self.middleware.oidc.return_value = False
        response = HttpResponse()
        with patch.object(SessionMiddleware, "process_response", return_value=response):
            self.assertIs(self.middleware.process_response(self.request, response), response)
        self.middleware.authority.guard.assert_not_called()

    def test_entry_failure_prevents_view_dispatch(self):
        self.middleware.authority.check.side_effect = ContractError("IDENTITY_UNAVAILABLE", "Unavailable", 503)
        replacement = HttpResponse(status=503)
        self.middleware.failure = Mock(return_value=replacement)
        with patch.object(SessionMiddleware, "process_request"):
            self.assertIs(self.middleware.process_request(self.request), replacement)
        self.middleware.authority.check.assert_called_once_with(self.request)
