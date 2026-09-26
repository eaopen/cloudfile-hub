"""Explicit process-owned deployment assembly; no feature enablement or URLs."""
from dataclasses import dataclass

from ..common.http import trusted_https_url
from ..common.validation import object_fields, identifier
from .assembly import session_policy_factory


@dataclass
class PolicyDeployment:
    factory: object
    redis: object
    resource_factory: object = None
    audit_factory: object = None

    def close(self):
        # The host invokes this only after draining all requests at shutdown.
        self.redis.connection_pool.disconnect()


def configure_policy(value, *, directory_authorization, resource_secret=None, lifecycle_reader=None,
                     audit_secret=None, audit_redact=None, audit_result_root=None):
    """value is trusted host settings, not request JSON or an import path.

    Matches the current native authority adapter: private Redis TCP, DB0, password
    authentication, no TLS/ACL username. Do not claim unsupported transports work.
    """
    object_fields(value, ("database", "redis", "provider", "native_schema", "identity_schema",
                         "directory_url", "attribute_allowlist", "core_library", "cloud_mode"),
                         ("subject_prefix", "directory_ca_bundle"))
    database = value["database"]
    object_fields(database, ("host", "user", "name", "password"), ("port",))
    redis_settings = value["redis"]
    object_fields(redis_settings, ("host", "port", "password"))
    for settings, keys in ((database, ("host", "user", "name")), (redis_settings, ("host",))):
        for key in keys:
            identifier(settings[key])
    for settings in (database, redis_settings):
        if not isinstance(settings["password"], str) or "\x00" in settings["password"]:
            raise ValueError("invalid deployment password")
    db_port = database.get("port", 3306)
    redis_port = redis_settings["port"]
    if any(type(port) is not int or not 1 <= port <= 65535 for port in (db_port, redis_port)):
        raise ValueError("invalid deployment port")
    trusted_https_url(value["directory_url"])
    if not callable(directory_authorization):
        raise ValueError("machine directory credential supplier required")
    if audit_secret is None and (audit_redact is not None or audit_result_root is not None):
        raise ValueError("audit redaction requires an audit cursor secret")
    if audit_secret is not None and (not isinstance(audit_secret, bytes)
            or len(audit_secret) < 32 or (audit_redact is not None and not callable(audit_redact))):
        raise ValueError("trusted audit cursor secret and redaction required")
    if (resource_secret is None) != (lifecycle_reader is None):
        raise ValueError("resource secret and lifecycle adapter must be configured together")
    if resource_secret is not None and (not isinstance(resource_secret, bytes)
            or len(resource_secret) < 32 or not callable(lifecycle_reader)):
        raise ValueError("trusted resource secret and lifecycle adapter required")
    environment = {"CLOUDFILE_DB_" + key.upper(): str(item) for key, item in
        dict(host=database["host"], user=database["user"], name=database["name"],
             password=database["password"], port=db_port).items()}
    import redis
    client = redis.Redis(host=redis_settings["host"], port=redis_port, db=0,
        password=redis_settings["password"] or None, socket_connect_timeout=1,
        socket_timeout=1, retry_on_timeout=False, decode_responses=False,
        max_connections=32)
    try:
        factory = session_policy_factory(environment=environment, redis=client,
            provider_id=value["provider"], native_schema=value["native_schema"],
            identity_schema=value["identity_schema"], directory_url=value["directory_url"],
            authorization=directory_authorization, attribute_allowlist=value["attribute_allowlist"],
            core_library=value["core_library"], cloud_mode=value["cloud_mode"],
            prefix=value.get("subject_prefix", "cf:subjects:"),
            ca_bundle=value.get("directory_ca_bundle"))
        resource_factory = None
        if resource_secret is not None:
            from ..resources.runtime import ResourceServiceFactory
            resource_factory = ResourceServiceFactory(authenticate=factory.authenticate,
                preparation_scope=factory.preparation_scope, core=factory.core,
                cloud_mode=factory.cloud_mode, secret=resource_secret,
                lifecycle_reader=lifecycle_reader)
        audit_factory = None
        if audit_secret is not None:
            from ..events.runtime import AuditQueryFactory
            audit_factory = AuditQueryFactory(authenticate=factory.authenticate,
                preparation_scope=factory.preparation_scope, core=factory.core,
                cloud_mode=factory.cloud_mode, secret=audit_secret, redact=audit_redact,
                result_root=audit_result_root)
        return PolicyDeployment(factory, client, resource_factory, audit_factory)
    except Exception:
        client.connection_pool.disconnect()
        raise
