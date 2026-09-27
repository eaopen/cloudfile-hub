"""Explicit process-owned deployment assembly; no feature enablement or URLs."""
from dataclasses import dataclass

from ..common.http import trusted_https_url
from ..common.validation import object_fields, identifier
from .assembly import session_policy_factory
from .service_configuration import directory_authorization as resolve_directory_authorization
from .service_configuration import parse_service_runtime


@dataclass
class PolicyDeployment:
    factory: object
    redis: object
    resource_factory: object = None
    audit_factory: object = None
    context_factory: object = None
    refresh_factory: object = None
    service_refresh_factory: object = None
    delegation_issue_factory: object = None
    login_resources: object = None
    local_session_factory: object = None
    local_device_factory: object = None
    local_agent_runtime: object = None
    local_read_issuer: object = None

    def close(self):
        # The host invokes this only after draining all requests at shutdown.
        self.redis.connection_pool.disconnect()


def configure_policy(value, *, directory_authorization, resource_secret=None, lifecycle_reader=None,
                     audit_secret=None, audit_redact=None, audit_result_root=None,
                     refresh_service_verifier=None, refresh_provider_grants=None,
                     delegation_service_verifier=None, delegation_signing_keys=None,
                     oidc=None, oidc_jit_enabled=False, local_edit_instance=None,
                     local_edit_version_reader=None, local_edit_enabled=False,
                     authorization_enabled=False):
    """value is trusted host settings, not request JSON or an import path.

    Matches the current native authority adapter: private Redis TCP, DB0, password
    authentication, no TLS/ACL username. Do not claim unsupported transports work.
    """
    object_fields(value, ("database", "redis", "provider", "native_schema", "identity_schema",
                         "directory_url", "attribute_allowlist", "core_library", "cloud_mode"),
                         ("subject_prefix", "directory_ca_bundle", "directory_bearer_token",
                          "service_credentials", "refresh_provider_grants",
                          "delegation_signing_keys", "service_revocation_prefix"))
    if type(oidc_jit_enabled) is not bool or (oidc is None and oidc_jit_enabled):
        raise ValueError("explicit OIDC configuration required before JIT")
    if type(local_edit_enabled) is not bool:
        raise ValueError("explicit local edit enablement required")
    if type(authorization_enabled) is not bool:
        raise ValueError("explicit authorization enablement required")
    if oidc is not None:
        from ..identity.oidc import OIDCConfig
        if not isinstance(oidc, OIDCConfig):
            raise ValueError("trusted validated OIDC configuration required")
        subject_prefix = value.get("subject_prefix", "cf:subjects:")
        if not isinstance(subject_prefix, str) or not subject_prefix.endswith(":subjects:"):
            raise ValueError("OIDC and policy require the same subject namespace")
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
    directory_authorization = resolve_directory_authorization(value, directory_authorization)
    service_runtime = parse_service_runtime(value, provider=value["provider"])
    if service_runtime is not None and any(item is not None for item in
            (refresh_service_verifier, refresh_provider_grants,
             delegation_service_verifier, delegation_signing_keys)):
        raise ValueError("service security runtime is configured twice")
    if (refresh_service_verifier is None) != (refresh_provider_grants is None):
        raise ValueError("machine refresh verifier and provider grants required together")
    if (delegation_service_verifier is None) != (delegation_signing_keys is None):
        raise ValueError("delegation verifier and signing keys required together")
    if authorization_enabled and service_runtime is None and (refresh_service_verifier is None
            or delegation_service_verifier is None):
        raise ValueError("enabled authorization requires refresh and delegation service runtimes")
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
    if (local_edit_instance is None) != (local_edit_version_reader is None):
        raise ValueError("local edit origin and native version adapter are required together")
    if local_edit_instance is not None and resource_secret is None:
        raise ValueError("local edit requires the configured resource runtime")
    if local_edit_enabled and (local_edit_instance is None or resource_secret is None or
            not callable(lifecycle_reader) or not callable(local_edit_version_reader)):
        raise ValueError("enabled local edit requires origin and native lifecycle/version adapters")
    environment = {"CLOUDFILE_DB_" + key.upper(): str(item) for key, item in
        dict(host=database["host"], user=database["user"], name=database["name"],
             password=database["password"], port=db_port).items()}
    import redis
    client = redis.Redis(host=redis_settings["host"], port=redis_port, db=0,
        password=redis_settings["password"] or None, socket_connect_timeout=1,
        socket_timeout=1, retry_on_timeout=False, decode_responses=False,
        max_connections=32)
    try:
        if service_runtime is not None:
            (refresh_service_verifier, refresh_provider_grants,
             delegation_service_verifier, delegation_signing_keys) = service_runtime.build(client)
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
        from ..directory.self_context import OwnContextFactory
        context_factory = OwnContextFactory(authenticate=factory.authenticate,
            preparation_scope=factory.preparation_scope, core=factory.core,
            cloud_mode=factory.cloud_mode)
        from ..directory.refresh_factory import UserRefreshFactory
        refresh_factory = UserRefreshFactory(authenticate=factory.authenticate,
            preparation_scope=factory.preparation_scope, core=factory.core, cloud_mode=factory.cloud_mode)
        service_refresh_factory = None
        if refresh_service_verifier is not None:
            from ..directory.service_refresh import ServiceRefreshFactory
            service_refresh_factory = ServiceRefreshFactory(verifier=refresh_service_verifier,
                resources=factory.resources, provider_grants=refresh_provider_grants)
        delegation_issue_factory = None
        if delegation_service_verifier is not None:
            from ..identity.delegation_issue import UserDelegationIssueFactory
            delegation_issue_factory = UserDelegationIssueFactory(resources=factory.resources,
                core=factory.core, service_verifier=delegation_service_verifier,
                signing_keys=delegation_signing_keys, cloud_mode=factory.cloud_mode)
        login_resources = None
        if oidc is not None:
            from ..identity.resources import LoginResources
            prefix = factory.resources.prefix[:-len("subjects:")]
            login_resources = LoginResources(factory.resources, oidc=oidc,
                jit_enabled=oidc_jit_enabled, prefix=prefix)
        local_session_factory = local_device_factory = local_agent_runtime = local_read_issuer = None
        if local_edit_instance is not None:
            from ..local_edit.agent_runtime import AgentClaimRuntime
            from ..local_edit.device_runtime import DeviceManagementFactory
            from ..local_edit.read_ticket import AgentReadTicketIssuer
            from ..local_edit.session_runtime import LocalSessionFactory
            local_session_factory = LocalSessionFactory(resource_factory, instance=local_edit_instance,
                version_reader=local_edit_version_reader)
            local_device_factory = DeviceManagementFactory(factory, instance=local_edit_instance)
            local_agent_runtime = AgentClaimRuntime(factory.resources, factory.core,
                instance=local_edit_instance, cloud_mode=factory.cloud_mode, secret=resource_secret,
                lifecycle_reader=lifecycle_reader, version_reader=local_edit_version_reader)
            local_read_issuer = AgentReadTicketIssuer(local_agent_runtime)
        return PolicyDeployment(factory=factory, redis=client, resource_factory=resource_factory,
            audit_factory=audit_factory, context_factory=context_factory,
            refresh_factory=refresh_factory, service_refresh_factory=service_refresh_factory,
            delegation_issue_factory=delegation_issue_factory,
            login_resources=login_resources, local_session_factory=local_session_factory,
            local_device_factory=local_device_factory, local_agent_runtime=local_agent_runtime,
            local_read_issuer=local_read_issuer)
    except Exception:
        client.connection_pool.disconnect()
        raise
