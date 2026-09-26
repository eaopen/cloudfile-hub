"""Owned current OIDC session authority for native request/effect hosts."""
from contextlib import contextmanager
from copy import deepcopy

from ..common.errors import ContractError
from ..jobs.authority import scope_locks
from .resources import LoginResources
from .session_index import OIDCSessionIndex
from .session_delete import NativeDBSessionDelete
from .native_session import BACKEND, SESSION_REFERENCE_KEY


class OIDCSessionAuthority:
    def __init__(self, resources):
        if not isinstance(resources, LoginResources):
            raise ValueError("actual owned login resources required")
        self.resources = resources

    @contextmanager
    def guard(self, request):
        from seahub.auth import BACKEND_SESSION_KEY
        if not request.is_secure() or request.session.get(BACKEND_SESSION_KEY) != BACKEND:
            raise ContractError("AUTHENTICATION_REQUIRED", "Native OIDC session is required", 401)
        key = request.session.session_key
        reference = request.session.get(SESSION_REFERENCE_KEY)
        config = self.resources.oidc
        with self.resources.resources.connection() as connection:
            index = OIDCSessionIndex(connection, issuer=config.issuer, client_id=config.client_id)
            deletion = NativeDBSessionDelete(index,
                identity_schema=self.resources.resources.identity_schema)
            with scope_locks(connection, [index.scope]):
                connection.begin()
                try:
                    with connection.cursor() as cursor:
                        deletion.assert_current(cursor, key, reference)
                        yield cursor
                        # Prevent a host from rotating/replacing its session
                        # while attributing an effect to this old grant.
                        if (request.session.session_key != key
                                or request.session.get(BACKEND_SESSION_KEY) != BACKEND
                                or request.session.get(SESSION_REFERENCE_KEY) != reference):
                            raise ContractError("AUTHENTICATION_REQUIRED", "Native OIDC session changed", 401)
                        deletion.sync_expiry(cursor, key, reference)
                        deletion.assert_current(cursor, key, reference)
                    connection.commit()
                finally:
                    connection.rollback()

    def check(self, request):
        with self.guard(request):
            pass

    def terminate(self, request, native_logout):
        """End the browser first, then retire only its captured server reference.

        Never require a live native session after flush and never publish a
        subject-wide fence for a local logout. SQL failure cannot restore login.
        """
        from seahub.auth import BACKEND_SESSION_KEY
        oidc = request.session.get(BACKEND_SESSION_KEY) == BACKEND
        key = request.session.session_key
        reference = deepcopy(request.session.get(SESSION_REFERENCE_KEY)) if oidc else None
        try:
            native_logout(request)
        finally:
            if oidc:
                config = self.resources.oidc
                with self.resources.resources.connection() as connection:
                    index = OIDCSessionIndex(connection, issuer=config.issuer,
                        client_id=config.client_id)
                    with scope_locks(connection, [index.scope]):
                        connection.begin()
                        try:
                            with connection.cursor() as cursor:
                                index.forget_reference(cursor, key, reference)
                            connection.commit()
                        finally:
                            connection.rollback()


class HostedOIDCSessionAuthority(OIDCSessionAuthority):
    """Late process-owned scope for middleware save and each stream checkpoint.

    No preload-master Redis handle is retained. The actual authority still
    performs signed native-session/SQL/fence checks; the host scope only controls
    lifecycle ownership and cannot grant access by returning a boolean.
    """
    def __init__(self, resources_scope):
        if not callable(resources_scope):
            raise ValueError("trusted process-owned login scope required")
        self.resources_scope = resources_scope

    @contextmanager
    def guard(self, request):
        with self.resources_scope() as resources:
            authority = OIDCSessionAuthority(resources)
            with authority.guard(request) as cursor:
                yield cursor

    def terminate(self, request, native_logout):
        with self.resources_scope() as resources:
            OIDCSessionAuthority(resources).terminate(request, native_logout)
