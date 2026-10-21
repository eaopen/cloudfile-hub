"""Opt-in system-administrator control plane over the native ACL store.

Accepts the existing authenticated Seahub administrator, never an asserted
business user. It shares the native transactions, revisions and retry ledger.
"""
from contextlib import contextmanager
from uuid import uuid4

from django.conf import settings
from rest_framework.response import Response
from seahub.api2.endpoints.admin.library_administrator import AdminLibraryAdministrator
from seaserv import seafile_api

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields
from ..resources.paths import resource_ref
from .admin_management import SystemAdministratorManagement, NativeAdministratorResources
from .share_service import DirectoryShareService
from .http import DirectoryPolicyView



class AdministratorPolicyView(AdminLibraryAdministrator):
    http_method_names = ('get', 'post', 'put', 'delete')
    library_page = False
    shares = False

    @contextmanager
    def rules(self, request, reference, request_id):
        if getattr(settings, 'CLOUDFILE_ADMIN_POLICY_ENABLED', True) is not True:
            raise ContractError('POLICY_UNAVAILABLE', 'Administrator policy is disabled', 503)
        user = request.user
        if (user.is_authenticated is not True or user.is_active is not True
                or user.is_staff is not True or not user.admin_permissions.can_manage_library()):
            raise ContractError('ACCESS_DENIED', 'System library management is required', 403)
        denied = self._authorize(request, reference['repo_id'])
        if denied is not None:
            raise ContractError('ACCESS_DENIED', 'Library management is not allowed', denied.status_code)
        # Native account authority is independent of the browser OIDC runtime.
        resources = NativeAdministratorResources()
        from ..resources.native import NativeResourceReader
        with resources.connection() as connection:
            authority = SystemAdministratorManagement(resources, connection,
                username=user.username, reference=reference, request_id=request_id,
                authorize_library=lambda ref: self._authorize(request, ref['repo_id']) is None,
                lifecycle_reader=NativeResourceReader(seafile_api))
            yield authority

    def run(self, request, rule_id=None):
        request_id = str(uuid4())
        try:
            if rule_id is not None:
                rule_id = str(rule_id)
            if request.method == 'GET':
                allowed = {'repo_id', 'limit', 'after'} if self.library_page else {
                    'repo_id', 'path', 'kind', 'limit', 'after'}
                if (set(request.GET) - allowed or
                        any(len(request.GET.getlist(k)) != 1 for k in request.GET)):
                    raise invalid('Invalid policy query')
                required = {'repo_id'} if self.library_page else {'repo_id', 'path', 'kind'}
                if not required <= set(request.GET) or rule_id is not None:
                    raise invalid('Policy target is required')
                reference = resource_ref(dict(repo_id=request.GET['repo_id'],
                    path='/' if self.library_page else request.GET['path'],
                    kind='dir' if self.library_page else request.GET['kind']))
                limit = request.GET.get('limit', '50')
                if not limit.isascii() or not limit.isdecimal() or not 1 <= int(limit) <= 100:
                    raise invalid('Invalid policy page limit')
                with self.rules(request, reference, request_id) as authority:
                    rules = authority.rules
                    result = (DirectoryShareService(authority, lifecycle_reader=rules.lifecycle_reader).list(
                        dict(reference=reference), limit=int(limit), after=request.GET.get('after')) if self.shares else
                        rules.list_library(reference['repo_id'], limit=int(limit),
                        after=request.GET.get('after')) if self.library_page else
                        rules.list_target(reference, limit=int(limit), after=request.GET.get('after')))
            else:
                if self.library_page or request.GET:
                    raise invalid('Invalid policy mutation target')
                length = request.META.get('CONTENT_LENGTH', '')
                if length and (not length.isdecimal() or int(length) > 16384):
                    raise ContractError('REQUEST_TOO_LARGE', 'Policy request exceeds its limit', 413)
                body = DirectoryPolicyView()._body(request._request)
                object_fields(body, ('reference',) if request.method == 'DELETE' else ('reference', 'value'))
                reference = resource_ref(body['reference'])
                if (request.method == 'POST' and rule_id is not None or
                        request.method in ('PUT', 'DELETE') and rule_id is None):
                    raise invalid('Invalid policy mutation target')
                with self.rules(request, reference, request_id) as authority:
                    rules = authority.rules
                    value = body.get('value')
                    if value is not None and (not isinstance(value, dict) or
                            not isinstance(value.get('subject'), dict) or
                            value['subject'].get('provider') != rules.provider):
                        raise invalid('Policy subject provider does not match this deployment')
                    if self.shares:
                        service = DirectoryShareService(authority, lifecycle_reader=rules.lifecycle_reader)
                        if request.method == 'POST':
                            result = service.create(body, idempotency_key=request.headers.get('Idempotency-Key'))
                        elif request.method == 'DELETE':
                            result = service.delete(rule_id, body, if_match=request.headers.get('If-Match'),
                                idempotency_key=request.headers.get('Idempotency-Key'))
                        else:
                            raise ContractError('METHOD_NOT_ALLOWED', 'Use ACL update to edit shared permissions', 405)
                    else:
                        result = rules.mutate(reference, value=value, rule_id=rule_id,
                            if_match=request.headers.get('If-Match'),
                            idempotency_key=request.headers.get('Idempotency-Key'))
            response = Response(result, status=201 if request.method == 'POST' else 200)
            response['Cache-Control'] = 'no-store'
            if result.get('etag'):
                response['ETag'] = result['etag']
            return response
        except ContractError as error:
            return Response(error.response(request_id), status=error.status)
        except Exception:
            return Response(dict(code='POLICY_UNAVAILABLE',
                message='Administrator policy operation is unavailable', request_id=request_id), status=503)

    def get(self, request, rule_id=None):
        return self.run(request, rule_id)

    def post(self, request, rule_id=None):
        return self.run(request, rule_id)

    def put(self, request, rule_id=None):
        return self.run(request, rule_id)

    def delete(self, request, rule_id=None):
        return self.run(request, rule_id)
