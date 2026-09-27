"""Explicit provider service credential plus current OIDC session and CSRF."""
import os
import re
from uuid import uuid4

from django.conf import settings
from django.http import JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from ..authorization import gunicorn
from ..authorization.http import DirectoryPolicyView
from ..common.errors import ContractError, invalid
from ..identity.service_revocations import ServiceRevocations
from ..identity.service_tokens import ServiceTokenVerifier
from .provider import SystemTagProvider


class SystemTagProviderView(DirectoryPolicyView):
    http_method_names = ['post']

    def dispatch(self, request, *args, **kwargs):
        request_id = str(uuid4())
        try:
            if request.method != 'POST' or args or kwargs:
                raise ContractError('METHOD_NOT_ALLOWED', 'System tags require POST', 405)
            if not request.is_secure():
                raise ContractError('AUTHENTICATION_REQUIRED', 'Secure provider session required', 401)
            if request.GET or request.headers.get('Authorization') or request.headers.get('Content-Encoding'):
                raise invalid('Provider session accepts no query, machine login or encoded body')
            csrf = CsrfViewMiddleware(lambda _: None)
            csrf.process_request(request)
            if csrf.process_view(request, lambda *_: None, (), {}) is not None:
                raise ContractError('ACCESS_DENIED', 'CSRF verification failed', 403)
            key = request.headers.get('Idempotency-Key')
            if key is None:
                raise ContractError('PRECONDITION_REQUIRED', 'Idempotency-Key is required', 428)
            if not re.fullmatch(r'[\x21-\x7e]{1,128}', key):
                raise invalid('Invalid provider request key')
            host = gunicorn._host
            if (getattr(settings, 'CLOUDFILE_SYSTEM_TAG_PROVIDER_ENABLED', False) is not True
                    or host is None or host.pid != os.getpid() or host.closed or host.draining):
                raise ContractError('RESOURCE_UNAVAILABLE', 'System tag provider is unavailable', 503)
            verifier = ServiceTokenVerifier(getattr(settings, 'CLOUDFILE_SYSTEM_TAG_PROVIDER_CREDENTIALS', None),
                revocations=ServiceRevocations(host.deployment.redis))
            provider = SystemTagProvider(verifier, getattr(settings, 'CLOUDFILE_SYSTEM_TAG_PROVIDER_GRANTS', None))
            body = self._body(request)
            with gunicorn.resource_service(request, request_id) as service:
                value, changed = provider.replace(service, body,
                    credential=request.headers.get('X-CloudFile-Provider-Authorization'), key=key)
            response = JsonResponse(value)
        except ContractError as error:
            response = JsonResponse(error.response(request_id), status=error.status)
        except Exception:
            error = ContractError('RESOURCE_UNAVAILABLE', 'System tag provider is unavailable', 503)
            response = JsonResponse(error.response(request_id), status=503)
        response['Cache-Control'] = 'no-store, max-age=0'
        response['Vary'] = 'Cookie, X-CloudFile-Provider-Authorization'
        response['X-Request-ID'] = request_id
        return response
