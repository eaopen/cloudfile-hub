"""Legacy OAuth sessions for shared browser lists; never OIDC transfer tickets.

The stored signed CE session, active account and exact Profile mapping remain
mandatory. OAuth provider tokens are neither consumed nor exposed here.
"""
from contextlib import contextmanager

from django.conf import settings

from ..common.errors import ContractError
from .native_session import BACKEND
from .read_ticket_http import native_download_actor, _native_actor
from .resources import LoginResources
from .session_authority import OIDCSessionAuthority
from .session_delete import NativeDBSessionDelete
from .session_index import OIDCSessionIndex

LEGACY_BACKEND = 'seahub.oauth.backends.OauthRemoteUserBackend'


def legacy_browser_actor(request):
    if (getattr(settings, 'ENABLE_OAUTH', False) is not True
            or LEGACY_BACKEND not in settings.AUTHENTICATION_BACKENDS):
        raise ContractError('AUTHENTICATION_REQUIRED', 'Legacy OAuth login is unavailable', 401)
    return _native_actor(request, backend=LEGACY_BACKEND)


class LegacyBrowserSessionAuthority:
    def __init__(self, resources):
        if not isinstance(resources, LoginResources):
            raise ValueError("actual owned login resources required")
        self.resources = resources

    def check(self, request):
        with self.guard(request):
            pass

    @contextmanager
    def guard(self, request):
        from seahub.auth import SESSION_KEY, BACKEND_SESSION_KEY
        actor = legacy_browser_actor(request)
        key = request.session.session_key
        if not key:
            raise ContractError('AUTHENTICATION_REQUIRED', 'Persisted browser session is required', 401)
        config = self.resources.oidc
        with self.resources.resources.connection() as connection:
            # Reuse the actual Django/SQL server co-location proof and signed
            # session decoder. Legacy sessions do not get an OIDC index entry.
            index = OIDCSessionIndex(connection, issuer=config.issuer, client_id=config.client_id)
            native = NativeDBSessionDelete(index,
                identity_schema=self.resources.resources.identity_schema)
            with connection.cursor() as cursor:
                cursor.execute("SELECT ENGINE FROM information_schema.tables "
                    "WHERE table_schema=%s AND table_name=%s",
                    (native.schema, native.table_name))
                if cursor.fetchall() != (("InnoDB",),):
                    raise ContractError("IDENTITY_UNAVAILABLE", "Transactional browser sessions are required", 503)
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    def current():
                        if (request.session.session_key != key
                                or request.session.get(BACKEND_SESSION_KEY) != LEGACY_BACKEND
                                or request.session.get(SESSION_KEY) != actor.native_username):
                            raise ContractError('AUTHENTICATION_REQUIRED', 'Browser session changed', 401)
                        cursor.execute('SELECT session_data FROM ' + native.table +
                            ' WHERE session_key=%s AND expire_date>UTC_TIMESTAMP(6) FOR UPDATE', (key,))
                        rows = cursor.fetchall()
                        data = native.decoder.decode(rows[0][0]) if len(rows) == 1 else {}
                        if (data.get(BACKEND_SESSION_KEY) != LEGACY_BACKEND
                                or data.get(SESSION_KEY) != actor.native_username):
                            raise ContractError('AUTHENTICATION_REQUIRED', 'Browser session ended or changed', 401)
                        if legacy_browser_actor(request) != actor:
                            raise ContractError('AUTHENTICATION_REQUIRED', 'Browser identity changed', 401)
                    current()
                    yield cursor
                    current()
                connection.commit()
            finally:
                connection.rollback()


def browser_session(request, resources):
    """Select by the server session backend, never by a client protocol hint."""
    from seahub.auth import BACKEND_SESSION_KEY
    session = getattr(request, 'session', None)
    if session is not None and session.get(BACKEND_SESSION_KEY) == BACKEND:
        return native_download_actor(request), OIDCSessionAuthority(resources)
    return legacy_browser_actor(request), LegacyBrowserSessionAuthority(resources)
