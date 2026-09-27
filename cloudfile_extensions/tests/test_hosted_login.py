"""Post-fork request ownership only; fixtures never prove actual authentication."""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from django.test import RequestFactory

from cloudfile_extensions.authorization.host import PolicyHost
from cloudfile_extensions.authorization import gunicorn
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.hosted_routes import HostedLoginView, hosted_login_routes
from cloudfile_extensions.identity.oidc import OIDCConfig
from cloudfile_extensions.identity.resources import LoginResources
from cloudfile_extensions.identity.session_authority import HostedOIDCSessionAuthority, OIDCSessionAuthority


class LoginHostTests(unittest.TestCase):
    def host(self, resources):
        deployment = SimpleNamespace(login_resources=resources, close=Mock())
        with patch("cloudfile_extensions.authorization.host.configure_policy", return_value=deployment):
            host = PolicyHost({}, directory_authorization=Mock())
        return host, deployment

    def test_whole_login_adapter_participates_in_drain(self):
        resources = object.__new__(LoginResources)
        host, deployment = self.host(resources)
        with host.login_resources_scope() as actual:
            self.assertIs(actual, resources)
            self.assertEqual(host.active, 1)
            self.assertFalse(host.drain())
            with self.assertRaises(ContractError):
                host.close()
            deployment.close.assert_not_called()
        self.assertEqual(host.active, 0)
        host.close()
        deployment.close.assert_called_once_with()
        with self.assertRaises(ContractError):
            with host.login_resources_scope():
                self.fail("drained login host accepted request")

    def test_missing_runtime_and_request_exception_release_count(self):
        host, _ = self.host(None)
        with self.assertRaises(ContractError):
            with host.login_resources_scope():
                self.fail("missing login resources accepted")
        self.assertEqual(host.active, 0)
        host, _ = self.host(object.__new__(LoginResources))
        with self.assertRaises(RuntimeError):
            with host.login_resources_scope():
                raise RuntimeError("fixture failure")
        self.assertEqual(host.active, 0)

    def test_parent_host_is_rejected_before_lock_or_resource_access(self):
        host, deployment = self.host(object.__new__(LoginResources))
        with patch("cloudfile_extensions.authorization.host.os.getpid", return_value=host.pid + 1):
            with self.assertRaises(ContractError):
                with host.login_resources_scope():
                    self.fail("inherited host accepted request")
        self.assertEqual(host.active, 0)
        deployment.close.assert_not_called()
        with patch.object(gunicorn, "_host", SimpleNamespace(pid=-1)):
            with self.assertRaises(ContractError):
                gunicorn.login_resources_scope()

    def test_oidc_config_repr_omits_secret(self):
        config = OIDCConfig(issuer="https://idp.invalid", client_id="cf",
            client_secret="fixture-private-secret", redirect_uri="https://cf.invalid/callback/",
            authorization_url="https://idp.invalid/authorize/", token_url="https://idp.invalid/token/",
            userinfo_url="https://idp.invalid/userinfo/", jwks_url="https://idp.invalid/jwks/")
        self.assertNotIn("fixture-private-secret", repr(config))

    def test_late_session_authority_holds_host_scope_through_actual_guard(self):
        events = []
        resources = object.__new__(LoginResources)
        @contextmanager
        def resources_scope():
            events.append("host-enter")
            try:
                yield resources
            finally:
                events.append("host-exit")
        @contextmanager
        def guard(request):
            events.append("sql-enter")
            try:
                yield "cursor"
            finally:
                events.append("sql-exit")
        actual = Mock(spec=OIDCSessionAuthority)
        actual.guard.side_effect = guard
        authority = HostedOIDCSessionAuthority(resources_scope)
        self.assertIsInstance(authority, OIDCSessionAuthority)
        with patch("cloudfile_extensions.identity.session_authority.OIDCSessionAuthority", return_value=actual) as construct:
            with authority.guard(object()) as cursor:
                self.assertEqual(cursor, "cursor")
                events.append("save")
            construct.assert_called_once_with(resources)
        self.assertEqual(events, ["host-enter", "sql-enter", "save", "sql-exit", "host-exit"])

    def test_late_session_authority_does_not_resolve_scope_at_construction(self):
        scope = Mock()
        HostedOIDCSessionAuthority(scope)
        scope.assert_not_called()


class HostedLoginHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def test_url_construction_does_not_resolve_preload_resources(self):
        scope = Mock()
        routes = hosted_login_routes(resources_scope=scope)
        self.assertEqual(len(routes), 6)
        self.assertEqual({str(route.pattern) for route in routes},
            {"begin/", "callback/", "pending/", "logout/", "logout/idp/", "logout/return/"})
        scope.assert_not_called()
        for target in ("//foreign.invalid/", "https://foreign.invalid/", "/a\\b"):
            with self.assertRaises(ValueError):
                hosted_login_routes(resources_scope=scope, return_path=target)

    def test_method_failure_still_owns_and_exits_whole_adapter_scope(self):
        events = []
        @contextmanager
        def resources_scope():
            events.append("entered")
            try:
                yield object.__new__(LoginResources)
            finally:
                events.append("exited")
        request = RequestFactory().post("/oidc/callback/", secure=True)
        response = HostedLoginView.as_view(resources_scope=resources_scope, operation="callback")(request)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(events, ["entered", "exited"])

    def test_only_explicit_server_notification_route_exempts_csrf(self):
        scope = Mock()
        routes = hosted_login_routes(resources_scope=scope, backchannel_enabled=True)
        self.assertEqual(len(routes), 7)
        exempt = [str(route.pattern) for route in routes if getattr(route.callback, 'csrf_exempt', False)]
        self.assertEqual(exempt, ['logout/backchannel/'])
        scope.assert_not_called()
        with self.assertRaises(ValueError):
            hosted_login_routes(resources_scope=scope, backchannel_enabled='true')

    def test_native_web_routes_require_explicit_enablement_and_keep_csrf(self):
        scope = Mock()
        routes = hosted_login_routes(resources_scope=scope, read_tickets_enabled=True)
        native = [route for route in routes if str(route.pattern) in {'read-tickets/', 'manual-update/'}]
        self.assertEqual(len(native), 2)
        self.assertTrue(all(not getattr(route.callback, 'csrf_exempt', False) for route in native))
        scope.assert_not_called()
        with self.assertRaises(ValueError):
            hosted_login_routes(resources_scope=scope, read_tickets_enabled='false')

    def test_uninitialized_worker_error_is_safe_uncached(self):
        @contextmanager
        def resources_scope():
            raise RuntimeError("private deployment diagnostic")
            yield
        response = HostedLoginView.as_view(resources_scope=resources_scope, operation="callback")(
            RequestFactory().get("/oidc/callback/", secure=True))
        self.assertEqual(response.status_code, 503)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotIn(b"private deployment diagnostic", response.content)
