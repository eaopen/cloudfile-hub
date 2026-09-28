"""Opt-in deployment wiring; no IdP/native-login completion claims."""
from copy import deepcopy
import os
import subprocess
import sys
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from django.core.exceptions import ImproperlyConfigured

from cloudfile_extensions.identity.configuration import (
    BACKEND, GUARDED_MIDDLEWARE, LOGIN_PREFIX, SESSION_MIDDLEWARE, configure_oidc_host,
)
from cloudfile_extensions.identity.oidc import OIDCConfig
from cloudfile_extensions.authorization import gunicorn


class OIDCHostConfigurationTests(unittest.TestCase):
    @staticmethod
    def configured():
        return SimpleNamespace(CLOUDFILE_OIDC_ENABLED=True,
            CLOUDFILE_POLICY_CONFIG={"provider": "fixture"},
            CLOUDFILE_OIDC_CONFIG=dict(issuer="https://idp.example/application/o/cloudfile/",
                client_id="cloudfile", client_secret="fixture-client-secret",
                redirect_uri="https://files.example/" + LOGIN_PREFIX + "callback/",
                authorization_url="https://idp.example/authorize/",
                token_url="https://idp.example/token/", userinfo_url="https://idp.example/userinfo/",
                jwks_url="https://idp.example/jwks/"),
            SESSION_ENGINE="django.contrib.sessions.backends.db",
            MIDDLEWARE=[SESSION_MIDDLEWARE, "seahub.auth.middleware.AuthenticationMiddleware"],
            AUTHENTICATION_BACKENDS=("seahub.base.accounts.SeafileBackend",), SITE_ROOT="/")

    def test_disabled_host_preserves_upstream_settings(self):
        settings = self.configured()
        settings.CLOUDFILE_OIDC_ENABLED = False
        before = deepcopy(vars(settings))
        configure_oidc_host(settings)
        self.assertEqual(vars(settings), before)

    def test_installs_guard_and_preserves_local_recovery_backend_idempotently(self):
        settings = self.configured()
        configure_oidc_host(settings)
        self.assertIsInstance(settings.CLOUDFILE_OIDC_CONFIG, OIDCConfig)
        self.assertEqual(settings.MIDDLEWARE[0], GUARDED_MIDDLEWARE)
        self.assertEqual(settings.AUTHENTICATION_BACKENDS,
            ("seahub.base.accounts.SeafileBackend", BACKEND))
        self.assertIs(settings.CLOUDFILE_OIDC_LOGIN_RESOURCE_SCOPE, gunicorn.login_resources_scope)
        self.assertTrue(settings.SESSION_COOKIE_SECURE)
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(settings.CSRF_COOKIE_SECURE)
        before = vars(settings).copy()
        configure_oidc_host(settings)
        self.assertEqual(vars(settings), before)

    def test_backchannel_requires_boolean_flag_and_enabled_oidc_host(self):
        for enabled, flag in [(False, True), (True, 'true')]:
            settings = self.configured()
            settings.CLOUDFILE_OIDC_ENABLED = enabled
            settings.CLOUDFILE_OIDC_BACKCHANNEL_ENABLED = flag
            before = vars(settings).copy()
            with self.assertRaises(ImproperlyConfigured):
                configure_oidc_host(settings)
            self.assertEqual(vars(settings), before)
        settings = self.configured()
        settings.CLOUDFILE_OIDC_BACKCHANNEL_ENABLED = True
        configure_oidc_host(settings)
        self.assertTrue(settings.CLOUDFILE_OIDC_BACKCHANNEL_ENABLED)

    def test_missing_policy_legacy_oauth_and_unguarded_sessions_rejected_without_mutation(self):
        for field, value in (("CLOUDFILE_POLICY_CONFIG", None), ("ENABLE_OAUTH", True),
                ("SESSION_ENGINE", "django.contrib.sessions.backends.cache"),
                ("MIDDLEWARE", []), ("MIDDLEWARE", [SESSION_MIDDLEWARE, GUARDED_MIDDLEWARE]),
                ("CLOUDFILE_OIDC_LOGIN_RESOURCES", object()),
                ("CLOUDFILE_OIDC_LOGIN_RESOURCE_SCOPE", Mock()),
                ("CLOUDFILE_OIDC_JIT_ENABLED", "true"), ("CLOUDFILE_OIDC_ENABLED", "true"),
                ("CLOUDFILE_OIDC_RETURN_PATH", "//other.example/")):
            with self.subTest(field=field, value=value):
                settings = self.configured()
                setattr(settings, field, value)
                before = vars(settings).copy()
                with self.assertRaises(ImproperlyConfigured) as error:
                    configure_oidc_host(settings)
                self.assertNotIn("fixture-client-secret", str(error.exception))
                self.assertEqual(vars(settings), before)

    def test_callback_and_logout_return_must_match_registered_routes(self):
        for uri in ("https://files.example/oauth/callback/",
                    "https://files.example/" + LOGIN_PREFIX + "callback/?next=/",
                    "https://files.example/" + LOGIN_PREFIX + "callback/#fragment"):
            settings = self.configured()
            settings.CLOUDFILE_OIDC_CONFIG["redirect_uri"] = uri
            with self.subTest(uri=uri), self.assertRaises(ImproperlyConfigured):
                configure_oidc_host(settings)
        settings = self.configured()
        settings.CLOUDFILE_OIDC_CONFIG.update(end_session_url="https://idp.example/logout/",
            post_logout_redirect_uri="https://files.example/wrong/")
        with self.assertRaises(ImproperlyConfigured):
            configure_oidc_host(settings)
        settings.CLOUDFILE_OIDC_CONFIG["post_logout_redirect_uri"] = (
            "https://files.example/" + LOGIN_PREFIX + "logout/return/")
        configure_oidc_host(settings)

    def test_site_root_prefix_is_part_of_callback_contract(self):
        settings = self.configured()
        settings.SITE_ROOT = "/files/"
        with self.assertRaises(ImproperlyConfigured):
            configure_oidc_host(settings)
        settings.CLOUDFILE_OIDC_CONFIG["redirect_uri"] = (
            "https://files.example/files/" + LOGIN_PREFIX + "callback/")
        configure_oidc_host(settings)
        self.assertEqual(settings.CLOUDFILE_OIDC_RETURN_PATH, "/files/")

    def test_enabled_routes_without_postfork_configuration_fail_startup(self):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only")
        from django.test import override_settings
        with override_settings(CLOUDFILE_OIDC_ENABLED=True, CLOUDFILE_POLICY_CONFIG=None), \
                patch.object(gunicorn, "_host", None):
            with self.assertRaises(RuntimeError):
                gunicorn.post_worker_init(Mock())

    def test_django_app_startup_installs_guard_before_hosted_urls_load(self):
        script = textwrap.dedent('''
            import sys, types
            from django.conf import settings
            from cloudfile_extensions.tests.test_oidc_configuration import OIDCHostConfigurationTests
            from cloudfile_extensions.identity.configuration import BACKEND, GUARDED_MIDDLEWARE, LOGIN_PREFIX
            values = vars(OIDCHostConfigurationTests.configured())
            settings.configure(**values, SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"],
                ROOT_URLCONF="cloudfile_extensions.root_urls", INSTALLED_APPS=["cloudfile_extensions"],
                REST_FRAMEWORK={"UNAUTHENTICATED_USER": None})
            import django
            django.setup()
            assert settings.MIDDLEWARE[0] == GUARDED_MIDDLEWARE
            assert BACKEND in settings.AUTHENTICATION_BACKENDS
            from rest_framework.views import APIView
            base = types.ModuleType("seahub.api2.base")
            base.APIView = APIView
            sys.modules[base.__name__] = base
            configuration = types.ModuleType("cloudfile_extensions.library_configuration")
            configuration.LibraryConfiguration = type("LibraryConfiguration", (APIView,), {})
            sys.modules[configuration.__name__] = configuration
            native = types.ModuleType("seahub.urls")
            native.urlpatterns = []
            sys.modules[native.__name__] = native
            from django.urls import resolve
            from django.test import RequestFactory
            from cloudfile_extensions.authorization import gunicorn
            for route in ("begin/", "callback/", "pending/", "logout/", "logout/idp/", "logout/return/"):
                path = "/" + LOGIN_PREFIX + route
                match = resolve(path)
                assert match.url_name.startswith("cloudfile-oidc-")
                response = match.func(RequestFactory().get(path, secure=True))
                assert response.status_code == 503
                assert "no-store" in response["Cache-Control"]
            assert gunicorn._host is None  # URL loading never constructs master-owned resources.
            from cloudfile_extensions.registry import registry
            assert not registry.implementations["auth.oidc"].implemented
        ''')
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(os.environ.get("CF_TEST_ACL_LIBRARY") and os.environ.get("CF_TEST_REDIS_PORT"),
                         "requires compiled C ACL core and isolated Redis")
    def test_postfork_oidc_host_uses_actual_core_and_redis_without_contacting_idp(self):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only")
        from django.test import override_settings
        from cloudfile_extensions.identity.resources import LoginResources
        oidc = OIDCConfig(**self.configured().CLOUDFILE_OIDC_CONFIG)
        value = dict(database=dict(host="unused.invalid", user="fixture", name="cloudfile", password=""),
            redis=dict(host=os.environ.get("CF_TEST_REDIS_HOST", "redis"),
                port=int(os.environ["CF_TEST_REDIS_PORT"]), password=""),
            provider="etech", native_schema="ccnet_db", identity_schema="seahub_db",
            directory_url="https://directory.invalid/v2", directory_bearer_token="fixture",
            attribute_allowlist=[], core_library=os.environ["CF_TEST_ACL_LIBRARY"], cloud_mode=False)
        with override_settings(CLOUDFILE_OIDC_ENABLED=True, CLOUDFILE_POLICY_CONFIG=value,
                CLOUDFILE_OIDC_CONFIG=oidc, CLOUDFILE_LOCAL_EDIT_ENABLED=False,
                CLOUDFILE_AUTHORIZATION_ENABLED=False, CLOUDFILE_TRANSFER_ENABLED=False), \
                patch.object(gunicorn, "_host", None):
            try:
                gunicorn.post_worker_init(SimpleNamespace())
                self.assertTrue(gunicorn._host.deployment.redis.ping())
                with gunicorn.login_resources_scope() as resources:
                    self.assertIsInstance(resources, LoginResources)
                    self.assertIs(resources.oidc, oidc)
                    self.assertIs(resources.resources.redis, gunicorn._host.deployment.redis)
                    self.assertEqual(gunicorn._host.active, 1)
            finally:
                gunicorn.worker_exit(None, SimpleNamespace(log=Mock()))
            self.assertIsNone(gunicorn._host)


if __name__ == "__main__":
    unittest.main()
