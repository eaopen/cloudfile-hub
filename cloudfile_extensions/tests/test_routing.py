"""Django URL composition integration; upstream handlers are isolated fixtures.

Seafile RPC/runtime regression must be run separately in the built CE container.
"""
import importlib.util
import subprocess
import sys
import textwrap
import unittest


@unittest.skipUnless(importlib.util.find_spec("django"), "requires the Hub Django runtime")
class RoutingTest(unittest.TestCase):
    def test_composition_preserves_native_routes_and_reserves_core_domains(self):
        script = textwrap.dedent('''
            import importlib
            import sys
            import types
            from django.conf import settings
            settings.configure(SECRET_KEY="test-only", ROOT_URLCONF="cloudfile_extensions.root_urls",
                ALLOWED_HOSTS=["testserver"], INSTALLED_APPS=[],
                REST_FRAMEWORK={"UNAUTHENTICATED_USER": None},
                CLOUDFILE_EXTENSION_URLCONFS={"project": "cf_test_project"},
                CLOUDFILE_AUTHORIZATION_ENABLED=True,
                CLOUDFILE_LOCAL_EDIT_ENABLED=True,
                CLOUDFILE_TRANSFER_ENABLED=True,
                CLOUDFILE_AUDIT_QUERY_ENABLED=True,
                CLOUDFILE_CAPABILITIES={"auth.oidc": True})
            import django
            django.setup()
            from django.http import JsonResponse
            from django.urls import path, clear_url_caches, resolve
            from django.test import Client
            from rest_framework.views import APIView
            from rest_framework.authentication import BaseAuthentication
            from rest_framework.throttling import BaseThrottle
            base = types.ModuleType("seahub.api2.base")
            base.APIView = APIView
            sys.modules[base.__name__] = base
            authentication = types.ModuleType("seahub.api2.authentication")
            authentication.TokenAuthentication = type("TokenAuthentication", (BaseAuthentication,), {
                "authenticate": lambda self, request: None})
            sys.modules[authentication.__name__] = authentication
            throttling = types.ModuleType("seahub.api2.throttling")
            throttling.UserRateThrottle = type("UserRateThrottle", (BaseThrottle,), {
                "allow_request": lambda self, request, view: True})
            sys.modules[throttling.__name__] = throttling
            directory_sync = types.ModuleType("cloudfile_extensions.directory.sync_http")
            directory_sync.DirectorySync = type("DirectorySync", (APIView,), {})
            sys.modules[directory_sync.__name__] = directory_sync
            configuration = types.ModuleType("cloudfile_extensions.library_configuration")
            configuration.LibraryConfiguration = type("LibraryConfiguration", (APIView,), {})
            sys.modules[configuration.__name__] = configuration
            shares = types.ModuleType("cloudfile_extensions.library_shares")
            shares.LibrarySharesDesired = type("LibrarySharesDesired", (APIView,), {})
            sys.modules[shares.__name__] = shares
            native = types.ModuleType("seahub.urls")
            native.urlpatterns = [path("api/v2.1/native/", lambda r: JsonResponse({"native": True}))]
            sys.modules[native.__name__] = native
            project = types.ModuleType("cf_test_project")
            project.urlpatterns = [path("ping/", lambda r: JsonResponse({"project": True}))]
            sys.modules[project.__name__] = project
            client = Client()
            assert client.get("/api/v2.1/native/").json() == {"native": True}
            assert client.get("/api/v2.1/cloudfile/extensions/project/ping/").json() == {"project": True}
            assert client.post("/api/v2.1/cloudfile/extensions/local-edit/v1/agent/challenge/").status_code == 401
            context_response = client.get("/api/v2.1/cloudfile/extensions/authorization/v1/contexts/me/")
            assert context_response.status_code == 401, (context_response.status_code, context_response.content)
            delegation_response = client.post("/api/v2.1/cloudfile/extensions/authorization/v1/delegations/")
            assert delegation_response.status_code == 401, (delegation_response.status_code, delegation_response.content)
            delegated_read = client.post(
                "/api/v2.1/cloudfile/extensions/transfer/v1/delegated-read-tickets/")
            assert delegated_read.status_code == 401, (delegated_read.status_code, delegated_read.content)
            audit = client.get("/api/v2.1/cloudfile/extensions/audit/v1/events/library/operations/",
                {"repo_id": "11111111-1111-4111-8111-111111111111",
                 "start": "2026-09-01T00:00:00Z", "end": "2026-09-02T00:00:00Z"}, secure=True)
            assert audit.status_code == 503, (audit.status_code, audit.content)
            assert resolve("/api/v2.1/cloudfile/extensions/audit/v1/admin/login/").url_name == "cloudfile-admin-audit"
            assert resolve("/api/v2.1/cloudfile/extensions/authorization/v1/library-rules/").url_name == "library-policy-rules"
            assert resolve("/api/v2.1/cloudfile/libraries/11111111-1111-4111-8111-111111111111/shares/desired/").url_name == "library-shares-desired"
            response = client.get("/api/v2.1/cloudfile/capabilities/")
            assert response.status_code == 200
            assert response.json()["capabilities"]["auth.oidc"]["enabled"] is False
            assert response.json()["capabilities"]["audit.log"]["enabled"] is False
            assert client.get("/api/v2.1/cloudfile/extensions/annotations/v1/resources/").status_code == 404
            # Current .NET device/read routes and next-generation editing routes
            # coexist by capability, never by client language or replacement URL.
            from django.urls import Resolver404
            agent_prefix = "/api/v2.1/cloudfile/extensions/local-edit/v1/agent/"
            agent_operations = ("challenge", "claim", "read-challenge", "read-ticket",
                "renew-challenge", "renew", "cancel-challenge", "cancel")
            for operation in agent_operations:
                assert resolve(agent_prefix + operation + "/").url_name == "local-agent-" + operation
            edit_prefix = "/api/v2.1/cloudfile/extensions/editing/v1/"
            try:
                resolve(edit_prefix + "checkout/")
            except Resolver404:
                pass
            else:
                raise AssertionError("editing is mounted by default")
            root = importlib.import_module("cloudfile_extensions.root_urls")
            settings.CLOUDFILE_EDITING_ENABLED = True
            importlib.reload(root)
            clear_url_caches()
            for operation in ("status", "checkout", "heartbeat", "resume", "abandon",
                    "cancel", "checkin", "commit-file"):
                assert resolve(edit_prefix + operation + "/").url_name == "editing-" + operation
            for operation in agent_operations:
                assert resolve(agent_prefix + operation + "/").url_name == "local-agent-" + operation
            assert client.post(edit_prefix + "checkout/").status_code == 401
            settings.CLOUDFILE_EDITING_ENABLED = False
            importlib.reload(root)
            clear_url_caches()
            assert client.post(agent_prefix + "challenge/").status_code == 401
            assert client.post(edit_prefix + "checkout/").status_code == 404
            from django.core.exceptions import ImproperlyConfigured
            from cloudfile_extensions.registry import RESERVED_DOMAINS
            root = importlib.import_module("cloudfile_extensions.root_urls")
            for domain in RESERVED_DOMAINS:
                settings.CLOUDFILE_EXTENSION_URLCONFS = {domain: "cf_test_project"}
                clear_url_caches()
                try:
                    importlib.reload(root)
                except ImproperlyConfigured:
                    pass
                else:
                    raise AssertionError("reserved domain accepted: " + domain)
        ''')
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
