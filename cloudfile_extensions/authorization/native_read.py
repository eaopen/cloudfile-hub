"""Native authenticated metadata reads using the existing EAP directory.

The administrator policy channel writes rules but cannot grant content access.
This adapter reuses native login/token authentication and the same C policy,
subject epochs and SQL authority locks as the OIDC content runtime. No OIDC
client, administrator impersonation or additional deployment secret is needed.
"""
import logging
import os
from contextlib import contextmanager
from uuid import uuid4

from ..common.errors import ContractError
from ..directory.provider import DirectoryProvider
from ..directory.protocol import validate_subject
from ..directory.native_state import NativeSubjectState
from ..directory.preparation import SubjectPreparation
from .admin_management import NativeAdministratorResources
from .core import PolicyCore
from .scoped_read import ScopedContentReadAuthority

logger = logging.getLogger(__name__)
ATTRIBUTES = frozenset(('employee_no', 'display_name', 'email'))
CORE = '/opt/seafile/seafile-server-latest/seafile/lib/libcloudfile_acl.so.1'


def enabled():
    from django.conf import settings
    # Route ownership stays exclusive. Native reads accompany the native admin
    # channel, while the full OIDC channel retains its existing assembly.
    return (getattr(settings, 'CF_ENABLE_SSO', False) is True
            and not getattr(settings, 'CLOUDFILE_AUTHORIZATION_ENABLED', False)
            and getattr(settings, 'CLOUDFILE_ADMIN_POLICY_ENABLED', True) is True)


class ExistingDirectoryProvider(DirectoryProvider):
    def __init__(self):
        from cloudfile_ext.sso.directory import active, ExternalServiceDirectory
        from cloudfile_ext.registry import registry
        self.directory = active(registry)
        if not isinstance(self.directory, ExternalServiceDirectory):
            raise ContractError('SUBJECT_UNAVAILABLE', 'Authenticated directory is unavailable', 503)
        if self.directory._client().auth_mode != 'v2':
            raise ContractError('SUBJECT_UNAVAILABLE', 'Scoped directory authentication is required', 503)
        self.attribute_allowlist = ATTRIBUTES

    def fetch(self, user_id):
        try:
            subject = validate_subject(self.directory.context_for_user_id(user_id),
                requested_user_id=user_id, attribute_allowlist=self.attribute_allowlist)
            if 'organization_ancestors' not in subject:
                raise ValueError('incomplete organization context')
            return subject
        except Exception:
            raise ContractError('SUBJECT_UNAVAILABLE', 'Current directory subject is unavailable', 503) from None


def redis_client():
    import redis
    # Reuse the installed server's Redis endpoint; the authority namespace and
    # DB remain identical to v0.9 and are never derived from a request.
    host = os.environ.get('REDIS_HOST')
    if not host:
        raise ContractError('POLICY_UNAVAILABLE', 'Native subject cache is unavailable', 503)
    return redis.Redis(host=host, port=int(os.environ.get('REDIS_PORT', '6379')),
        password=os.environ.get('REDIS_PASSWORD') or None, db=0,
        socket_connect_timeout=1, socket_timeout=2, decode_responses=False)


@contextmanager
def authority(request, request_id):
    if not enabled():
        raise ContractError('POLICY_UNAVAILABLE', 'Native content runtime is disabled', 503)
    user = request.user
    if user.is_authenticated is not True or user.is_active is not True:
        raise ContractError('AUTHENTICATION_REQUIRED', 'Native authentication is required', 401)
    resources = NativeAdministratorResources()  # Storage only, never admin authority.
    client = redis_client()
    try:
        directory = ExistingDirectoryProvider()
        core = PolicyCore(CORE)
        with resources.connection() as connection:
            state = NativeSubjectState(connection, native_schema=resources.native_schema,
                identity_schema=resources.identity_schema, provider=resources.provider)
            actor = state.user_id(user.username)
            if not state.account_active(actor):
                raise ContractError('ACCESS_DENIED', 'Native account is inactive', 403)
            preparation = SubjectPreparation(connection, client, provider_id=resources.provider,
                directory=directory, native_schema=resources.native_schema,
                identity_schema=resources.identity_schema, actor_user_id=actor, request_id=request_id)
            from seaserv import seafile_api
            from ..resources.native import NativeResourceReader
            reader = NativeResourceReader(seafile_api)
            value = ScopedContentReadAuthority(preparation, core, request_id=request_id,
                cloud_mode=False, lifecycle_reader=reader)
            value.rules.lifecycle_reader = reader
            yield value
    finally:
        client.connection_pool.disconnect()


def ready():
    if not enabled():
        return False
    client = None
    try:
        ExistingDirectoryProvider()
        core = PolicyCore(CORE)
        # Directory shares require the scoped ABI; a basic ACL-only library is
        # not sufficient to advertise a working native content runtime.
        getattr(core.library, 'cf_acl_evaluate_scoped')
        client = redis_client()
        client.ping()
        with NativeAdministratorResources().connection():
            return True
    except Exception:
        return False
    finally:
        if client is not None:
            client.connection_pool.disconnect()


def response(request, operation):
    from rest_framework.response import Response
    request_id = str(uuid4())
    try:
        with authority(request, request_id) as current:
            result = Response(operation(current))
    except ContractError as error:
        logger.warning('Native content request failed: request_id=%s code=%s status=%s',
            request_id, error.code, error.status)
        result = Response(error.response(request_id), status=error.status)
    except Exception:
        logger.exception('Native content authorization failed: request_id=%s', request_id)
        error = ContractError('POLICY_UNAVAILABLE', 'Native content authority is unavailable', 503)
        result = Response(error.response(request_id), status=503)
    result['Cache-Control'] = 'no-store, max-age=0'
    result['Vary'] = 'Cookie, Authorization'
    result['X-Request-ID'] = request_id
    return result
