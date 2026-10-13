"""HTTP contract fixtures, not actual session/native authority evidence."""
from contextlib import contextmanager
import json
import unittest
from unittest.mock import Mock
from uuid import uuid4

from django.middleware.csrf import _get_new_csrf_string
from django.test import RequestFactory

from cloudfile_extensions.authorization.http import DirectoryPolicyView, DirectoryEffectiveView
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

    def test_real_routes_mount_collection_and_uuid_item_with_worker_factory(self):
        from django.urls import resolve
        from cloudfile_extensions.authorization.gunicorn import policy_service
        prefix = '/v1/directory-rules/'
        for url in (prefix, prefix + str(uuid4()) + '/'):
            target = resolve(url, urlconf='cloudfile_extensions.authorization.urls')
            self.assertIs(target.func.view_class, DirectoryPolicyView)
            self.assertIs(target.func.view_initkwargs['service_factory'], policy_service)

    def test_effective_route_only_queries_current_actor_and_fails_closed(self):
        from django.urls import resolve
        route = resolve('/v1/effective-permission/', urlconf='cloudfile_extensions.authorization.urls')
        self.assertIs(route.func.view_class, DirectoryEffectiveView)
        @contextmanager
        def factory(request, request_id):
            yield self.service
        view = DirectoryEffectiveView.as_view(service_factory=factory)
        self.service.effective.return_value = dict(native_permission='r', effective_permission='none', can_manage=False)
        response = view(self.requests.get('/effective/', data=self.ref, secure=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('no-store', response['Cache-Control'])
        self.service.effective.assert_called_once_with(dict(reference=self.ref))
        self.assertEqual(view(self.requests.get('/effective/', data={**self.ref, 'user': 'another'}, secure=True)).status_code, 400)
        self.assertEqual(DirectoryEffectiveView.as_view()(self.requests.get('/effective/', data=self.ref, secure=True)).status_code, 503)

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
        self.assertEqual(self.view(self.requests.get("/policy/", data=self.ref, secure=False)).status_code, 200)
        self.assertEqual(self.service.list.call_count, 1)

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

    def test_directory_routes_use_authenticated_factory(self):
        from django.urls import resolve
        from cloudfile_extensions.authorization.http import DirectoryAccessView
        from cloudfile_extensions.authorization.gunicorn import policy_service
        for domain in ('admins', 'shares'):
            for suffix in ('', str(uuid4()) + '/'):
                route = resolve('/v1/directory-' + domain + '/' + suffix,
                    urlconf='cloudfile_extensions.authorization.urls')
                self.assertIs(route.func.view_class, DirectoryPolicyView)
                self.assertEqual(route.func.view_initkwargs['domain'], domain)
                self.assertIs(route.func.view_initkwargs['service_factory'], policy_service)
        for name in ('shared-directories', 'directory-address'):
            route = resolve('/v1/' + name + '/', urlconf='cloudfile_extensions.authorization.urls')
            self.assertIs(route.func.view_class, DirectoryAccessView)
            self.assertIs(route.func.view_initkwargs['service_factory'], policy_service)

    def test_directory_access_rejects_actor_injection_and_sanitizes_errors(self):
        from cloudfile_extensions.authorization.directory_service import DirectoryService
        from cloudfile_extensions.authorization.http import DirectoryAccessView
        service = Mock(spec=DirectoryService)
        service.resolve_directory.return_value = dict(root_path='/a')
        service.shared_with_me.return_value = dict(items=[], next_after=None)
        @contextmanager
        def factory(request, request_id):
            yield service
        resolve = DirectoryAccessView.as_view(service_factory=factory)
        shared = DirectoryAccessView.as_view(service_factory=factory, operation='shared')
        response = resolve(self.requests.get('/address/', data=self.ref, secure=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('no-store', response['Cache-Control'])
        service.resolve_directory.assert_called_once_with(dict(reference=self.ref))
        self.assertEqual(resolve(self.requests.get('/address/', data={**self.ref, 'actor': 'other'}, secure=True)).status_code, 400)
        self.assertEqual(shared(self.requests.get('/shared/?limit=1&limit=2', secure=True)).status_code, 400)
        self.assertEqual(shared(self.requests.get('/shared/?limit=101', secure=True)).status_code, 400)
        self.assertEqual(shared(self.requests.get('/shared/?limit=1', secure=True)).status_code, 200)
        service.shared_with_me.side_effect = RuntimeError('private credentials')
        response = shared(self.requests.get('/shared/', secure=True))
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b'private credentials', response.content)

    def test_directory_entries_and_scope_routes_validate_transport_and_dispatch(self):
        from django.urls import resolve
        from cloudfile_extensions.authorization.directory_service import DirectoryService
        from cloudfile_extensions.authorization.http import DirectoryAccessView, DirectoryScopeView
        service = Mock(spec=DirectoryService)
        service.directory_entries.return_value = dict(items=[], head_id='a' * 40, next_after=None)
        service.list_scope.return_value = dict(items=[], next_after=None)
        service.revoke_scope.return_value = dict(items=[])
        @contextmanager
        def factory(request, request_id):
            yield service
        route = resolve('/v1/directory-entries/', urlconf='cloudfile_extensions.authorization.urls')
        self.assertIs(route.func.view_class, DirectoryAccessView)
        entries = DirectoryAccessView.as_view(service_factory=factory, operation='entries')
        self.assertEqual(entries(self.requests.get('/entries/', data={**self.ref, 'limit': '2'}, secure=True)).status_code, 200)
        service.directory_entries.assert_called_once_with(dict(reference=self.ref), limit=2, after=None)
        self.assertEqual(entries(self.requests.get('/entries/', data={**self.ref, 'limit': '101'}, secure=True)).status_code, 400)
        for operation in ('list', 'revoke'):
            route = resolve('/v1/directory-scope/' + operation + '/', urlconf='cloudfile_extensions.authorization.urls')
            self.assertIs(route.func.view_class, DirectoryScopeView)
            self.assertEqual(route.func.view_initkwargs.get('operation', 'list'), operation)
            view = DirectoryScopeView.as_view(service_factory=factory, operation=operation)
            body = dict(reference=self.ref, domain='shares')
            if operation == 'revoke':
                body['items'] = [dict(id=str(uuid4()), etag='"revision"')]
            self.assertEqual(view(self.write(json.dumps(body), csrf=False)).status_code, 403)
            response = view(self.write(json.dumps(body)))
            self.assertEqual(response.status_code, 200)
            self.assertIn('no-store', response['Cache-Control'])
            self.assertEqual(view(self.requests.get('/scope/', secure=True)).status_code, 405)
        service.list_scope.assert_called_once_with(dict(reference=self.ref, domain='shares'), limit=50, after=None)
        service.revoke_scope.assert_called_once_with(body, idempotency_key='create')
