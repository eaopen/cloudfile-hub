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
                CLOUDFILE_CAPABILITIES={"auth.oidc": True})
            import django
            django.setup()
            from django.http import JsonResponse
            from django.urls import path, clear_url_caches
            from django.test import Client
            from rest_framework.views import APIView
            base = types.ModuleType("seahub.api2.base")
            base.APIView = APIView
            sys.modules[base.__name__] = base
            native = types.ModuleType("seahub.urls")
            native.urlpatterns = [path("api/v2.1/native/", lambda r: JsonResponse({"native": True}))]
            sys.modules[native.__name__] = native
            project = types.ModuleType("cf_test_project")
            project.urlpatterns = [path("ping/", lambda r: JsonResponse({"project": True}))]
            sys.modules[project.__name__] = project
            client = Client()
            assert client.get("/api/v2.1/native/").json() == {"native": True}
            assert client.get("/api/v2.1/cloudfile/extensions/project/ping/").json() == {"project": True}
            response = client.get("/api/v2.1/cloudfile/capabilities/")
            assert response.status_code == 200
            assert response.json()["capabilities"]["auth.oidc"]["enabled"] is False
            assert client.get("/api/v2.1/cloudfile/extensions/annotations/v1/resources/").status_code == 404
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
