"""Runtime wiring for the reviewed subject TTL projector (work package A).

OAuth2 and OIDC logins call :func:`prepare_subject`, so one native account has
exactly one trusted stable UID subject. Every CloudFile-protected request calls
:func:`require_ready`, which reuses that published subject inside its TTL and
re-queries the Directory once the TTL is gone. Failing to prove the current
subject raises instead of trusting the previous native GroupUser rows.

The pure seam -- :func:`configuration` and :class:`MembershipRuntime` -- imports
no Django, MySQL or Redis module, so the reviewed projector stays testable
without a web stack. The adapters below own the native deployment facts and are
the only place that reads them.
"""
import os
import threading

from .directory_client import DirectoryClient, configuration as directory_configuration
from .errors import IdentityUnavailable, SubjectNotBound
from .identity import NativeAccountBinding, text
from .memberships import Memberships


DEFAULT_TTL = 1800
MINIMUM_TTL = 30
MAXIMUM_TTL = 1800
MAXIMUM_TIMEOUT = 30
DEFAULT_PROVIDER = 'etech'

_runtime_lock = threading.Lock()
_runtime = None
_state = threading.local()


def configuration(settings):
    """Use the shared short-lived Directory JWT, never a static bearer token."""
    url = getattr(settings, 'CF_DIRECTORY_URL', None)
    if not url:
        if any(getattr(settings, name, None) for name in
               ('CF_DIRECTORY_AUTH_SECRET', 'CF_DIRECTORY_AUTH_KEY_ID')):
            raise IdentityUnavailable('incomplete Directory service configuration')
        return None  # CE-only deployment uses native library permission.
    config = directory_configuration(settings)
    ttl = getattr(settings, 'CF_SUBJECT_TTL', DEFAULT_TTL)
    if type(ttl) is not int or not MINIMUM_TTL <= ttl <= MAXIMUM_TTL:
        raise IdentityUnavailable('CloudFile subject TTL out of range')
    config['ttl'] = ttl
    return config

class MembershipRuntime:
    """Fresh-subject policy over the reviewed projector.

    Collaborators are injected so the policy is verifiable without a database,
    Redis or HTTP provider. ``projector_factory`` receives the parsed
    configuration, the subject fetch callable and the readiness client.
    """

    def __init__(self, config, *, projector_factory, redis_factory, fetch_factory=None):
        self.config = config
        self.fetch = (fetch_factory if fetch_factory is not None else self._directory_client)(config)
        self.redis = redis_factory()
        self.projector_factory = projector_factory

    @staticmethod
    def _directory_client(config):
        return DirectoryClient(config).subject

    def _projector(self):
        return self.projector_factory(self.config, self.fetch, self.redis)

    def prepare_subject(self, username, uid):
        """Login: publish a subject fetched now, never a reused readiness record."""
        if not uid:
            raise SubjectNotBound('native account has no trusted stable UID')
        self._projector().ensure(uid, username, force=True)

    def require_ready(self, username, uid):
        """Protected request: reuse the subject inside its TTL, refresh after it."""
        if not uid:
            raise SubjectNotBound('native account has no trusted stable UID')
        self._projector().ensure(uid, username)


def _settings():
    from django.conf import settings
    return settings


def _native_schemas():
    """Native schema names, owned by the deployment; CloudFile never renames them."""
    default = _settings().DATABASES.get('default', {})
    files = os.environ.get('SEAFILE_MYSQL_DB_SEAFILE_DB_NAME')
    if not files:
        from seahub.utils.db_api import SeafileDB
        files = SeafileDB().db_name or 'seafile_db'
    return {
        'account': os.environ.get('SEAFILE_MYSQL_DB_CCNET_DB_NAME', 'ccnet_db'),
        'files': files,
        'hub': os.environ.get('SEAFILE_MYSQL_DB_SEAHUB_DB_NAME') or default.get('NAME') or 'seahub_db',
    }


def _mysql_connection(database):
    """One autocommit connection per worker thread, revalidated before reuse.

    ``Memberships`` needs a dedicated autocommit connection because it takes
    MySQL named locks and owns its own transactions.
    """
    connection = getattr(_state, 'connection', None)
    if connection is not None:
        try:
            connection.ping(reconnect=True)
            return connection
        except Exception:
            _close(connection)
    import pymysql
    default = _settings().DATABASES.get('default', {})
    connection = pymysql.connect(
        host=os.environ.get('SEAFILE_MYSQL_DB_HOST') or default.get('HOST') or '127.0.0.1',
        port=int(os.environ.get('SEAFILE_MYSQL_DB_PORT') or default.get('PORT') or 3306),
        user=os.environ.get('SEAFILE_MYSQL_DB_USER') or default.get('USER') or 'root',
        password=os.environ.get('SEAFILE_MYSQL_DB_PASSWORD') or default.get('PASSWORD') or '',
        database=database, charset='utf8mb4', autocommit=True, connect_timeout=5)
    _state.connection = connection
    return connection


def _close(connection):
    try:
        connection.close()
    except Exception:
        pass
    _state.connection = None


def _redis_client():
    """Readiness records require the deployment's Redis, never a generic cache."""
    import redis
    location = _settings().CACHES.get('default', {}).get('LOCATION')
    if not isinstance(location, str) or not location.startswith(('redis://', 'rediss://')):
        raise IdentityUnavailable('CloudFile subject readiness requires a redis cache')
    return redis.Redis.from_url(location, socket_timeout=5, socket_connect_timeout=5)


def _projector_factory(config, fetch, redis_client):
    schemas = _native_schemas()
    connection = _mysql_connection(schemas['files'])
    binding = NativeAccountBinding(connection, account_schema=schemas['account'],
                                   hub_schema=schemas['hub'])
    return Memberships(connection, redis_client, binding, account_schema=schemas['account'],
                       provider=config['provider'], fetch=fetch, ttl=config['ttl'])


def _runtime_for(settings):
    """Return the process runtime for this configuration, or None when disabled."""
    global _runtime
    config = configuration(settings)
    if config is None:
        return None
    if _runtime is None or _runtime.config != config:
        with _runtime_lock:
            if _runtime is None or _runtime.config != config:
                _runtime = MembershipRuntime(config, projector_factory=_projector_factory,
                                            redis_factory=_redis_client)
    return _runtime


def bound_uid(username):
    """The one trusted UID anchor: the native exact ``Profile.login_id`` binding.

    Native identity remains authoritative; CloudFile adds no second user table.
    A native account without that binding cannot prove a subject, so CloudFile
    resources stay closed for it.
    """
    from seahub.profile.models import Profile
    profile = Profile.objects.get_profile_by_user(username)
    uid = profile.login_id if profile is not None else None
    if not uid:
        raise SubjectNotBound('native account has no trusted stable UID')
    return uid


def prepare_subject(username, uid, settings=None):
    """Login-time subject publication. Returns False when V2 identity is off."""
    settings = _settings() if settings is None else settings
    runtime = _runtime_for(settings)
    if runtime is None:
        return False
    runtime.prepare_subject(username, uid)
    return True


def require_ready(username, settings=None):
    """Protected-request gate. Returns False when V2 identity is off."""
    settings = _settings() if settings is None else settings
    runtime = _runtime_for(settings)
    if runtime is None:
        return False
    runtime.require_ready(username, bound_uid(username))
    return True
