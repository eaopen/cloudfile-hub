"""Annotations Web protocol tests; service/authority boundary is mocked."""
from contextlib import contextmanager
import json
import unittest
from unittest.mock import Mock, patch

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory, override_settings

from cloudfile_extensions.authorization import gunicorn
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.http import (ResourceResolveView, ResourceAttributesView,
    ResourceUserTagValuesView, ResourceBatchView, UserTagDefinitionView, UserTagCatalogView)
from cloudfile_extensions.resources.routes import resource_routes
from cloudfile_extensions.resources.service import ResourceService


class ResourceHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if not settings.configured:
            settings.configure(SECRET_KEY="fixture-only", ALLOWED_HOSTS=["testserver"], DEFAULT_CHARSET="utf-8")
        import django
        django.setup()

    def setUp(self):
        self.requests = RequestFactory()
        self.ref = dict(repo_id="11111111-1111-4111-8111-111111111111", path="/file", kind="file")
        self.snapshot = dict(resource=self.ref, uid=None, revision="strong-revision", description="",
            local_open_type="cad.v1", tags=[], access=dict(read=True, write=True))
        self.service = Mock(spec=ResourceService)
        self.service.resolve.return_value = self.snapshot
        self.service.update_attributes.return_value = (self.snapshot, True)
        self.service.replace_user_tag_values.return_value = (self.snapshot, False)
        self.opened = 0
        @contextmanager
        def factory(request, request_id):
            self.opened += 1
            yield self.service
        self.factory = factory

    def request(self, body, method="post", **headers):
        token = _get_new_csrf_string()
        options = dict(HTTP_COOKIE="csrftoken=" + token, HTTP_X_CSRFTOKEN=token,
            HTTP_ORIGIN="https://testserver")
        options.update(headers)
        return getattr(self.requests, method)("/annotations/", data=json.dumps(body),
            content_type="application/json", secure=True, **options)

    def view(self, cls, request):
        return cls.as_view(service_factory=self.factory)(request)

    def test_resolve_uses_owned_scope_without_exposing_local_application_mapping(self):
        response = self.view(ResourceResolveView, self.request(self.ref))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("local_open_type", json.loads(response.content))
        self.assertEqual(self.snapshot["local_open_type"], "cad.v1")
        self.service.resolve.assert_called_once_with(dict(reference=self.ref))
        self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(response["Vary"], "Cookie, Authorization")

    def test_description_and_tag_saves_keep_condition_and_idempotency_key(self):
        body = dict(resource=self.ref, expected_revision="strong-revision", changes=dict(description="CAD"))
        response = self.view(ResourceAttributesView, self.request(body, HTTP_IDEMPOTENCY_KEY="save-1"))
        self.assertEqual(response.status_code, 201)
        self.service.update_attributes.assert_called_once_with(dict(reference=self.ref,
            revision="strong-revision", changes=dict(description="CAD")), idempotency_key="save-1")
        body = dict(reference=self.ref, revision="strong-revision", values=[dict(label="drawing")])
        response = self.view(ResourceUserTagValuesView, self.request(body, HTTP_IDEMPOTENCY_KEY="save-2"))
        self.assertEqual(response.status_code, 200)
        self.service.replace_user_tag_values.assert_called_once_with(body, idempotency_key="save-2")

    def test_v04_and_arbitrary_attributes_are_rejected_before_service_allocation(self):
        for changes in (dict(local_open_type="cad.v1"), dict(description="CAD", project="secret"), {}):
            body = dict(resource=self.ref, expected_revision="strong-revision", changes=changes)
            self.assertEqual(self.view(ResourceAttributesView,
                self.request(body, HTTP_IDEMPOTENCY_KEY="save")).status_code, 400)
        self.assertEqual(self.opened, 0)

    def test_missing_condition_headers_machine_credentials_and_csrf(self):
        body = dict(resource=self.ref, expected_revision="r", changes=dict(description=""))
        self.assertEqual(self.view(ResourceAttributesView, self.request(body)).status_code, 428)
        self.assertEqual(self.view(UserTagDefinitionView,
            self.request({}, method="patch", HTTP_IDEMPOTENCY_KEY="patch")).status_code, 428)
        for headers in (dict(HTTP_AUTHORIZATION="Bearer machine"), dict(HTTP_CONTENT_ENCODING="gzip")):
            self.assertEqual(self.view(ResourceResolveView, self.request(self.ref, **headers)).status_code, 400)
        request = self.requests.post("/annotations/", data=json.dumps(self.ref),
            content_type="application/json", secure=True)
        self.assertEqual(self.view(ResourceResolveView, request).status_code, 403)
        self.assertEqual(self.opened, 0)

    def test_conflict_and_revocation_are_not_reported_as_success(self):
        body = dict(reference=self.ref, revision="r", values=[])
        for status, code in ((409, "RESOURCE_REVISION_CONFLICT"), (403, "ACCESS_DENIED")):
            self.service.replace_user_tag_values.side_effect = ContractError(code, "Rejected", status)
            response = self.view(ResourceUserTagValuesView, self.request(body, HTTP_IDEMPOTENCY_KEY="save"))
            self.assertEqual(response.status_code, status)
            self.assertEqual(json.loads(response.content)["code"], code)

    def test_batch_hides_local_open_type_and_catalog_query_is_bounded(self):
        self.service.batch_resolve.return_value = dict(items=[dict(reference=self.ref, status=200,
            snapshot=self.snapshot), dict(reference=self.ref, status=404)])
        response = self.view(ResourceBatchView, self.request(dict(references=[self.ref])))
        items = json.loads(response.content)["items"]
        self.assertNotIn("local_open_type", items[0]["snapshot"])
        self.assertEqual(set(items[1]), {"reference", "status"})
        self.service.list_user_tag_definitions.return_value = dict(items=[], after=None)
        response = self.view(UserTagCatalogView, self.requests.get("/tags/",
            data=dict(repo_id=self.ref["repo_id"], limit=100), secure=True))
        self.assertEqual(response.status_code, 200)
        self.service.list_user_tag_definitions.assert_called_once_with(dict(repo_id=self.ref["repo_id"], limit=100))
        self.assertEqual(self.view(UserTagCatalogView, self.requests.get("/tags/",
            data=dict(repo_id=self.ref["repo_id"], limit=101), secure=True)).status_code, 400)

    def test_routes_are_explicit_and_enabled_without_lifecycle_fails_closed(self):
        self.assertEqual(len(resource_routes(service_factory=self.factory)), 7)
        for enabled in ("true", True):
            with override_settings(CLOUDFILE_ANNOTATIONS_ENABLED=enabled,
                    CLOUDFILE_OIDC_ENABLED=True, CLOUDFILE_RESOURCE_LIFECYCLE_READER=None), \
                    patch.object(gunicorn, "_host", None):
                with self.assertRaises(RuntimeError):
                    gunicorn.post_worker_init(Mock())
                self.assertIsNone(gunicorn._host)
