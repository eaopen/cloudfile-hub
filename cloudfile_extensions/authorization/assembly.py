"""Trusted CE session policy assembly; does not register or enable URLs."""
from ..common.http import HttpsJsonClient
from ..common.validation import identifier
from ..directory.provider import DirectoryProvider
from .core import PolicyCore
from .resources import PolicyResources
from .runtime import PolicyServiceFactory
from .seahub import SeahubPolicyAuthentication


def session_policy_factory(*, environment, redis, provider_id, native_schema,
                           identity_schema, directory_url, authorization,
                           attribute_allowlist, core_library, cloud_mode,
                           prefix="cf:subjects:", ca_bundle=None):
    """All arguments originate from deployment settings, never an HTTP body.

    The fixed Redis pool must use the same CF authority namespace as native
    publication. Caller owns process-wide pool shutdown; no credential logging.
    """
    identifier(provider_id, maximum=32)
    if not isinstance(prefix, str) or not prefix.startswith("cf:") or not prefix.endswith(":"):
        raise ValueError("explicit CloudFile subject namespace required")
    if not callable(authorization):
        raise ValueError("directory machine credential supplier required")
    if type(cloud_mode) is not bool:
        raise ValueError("explicit native cloud mode required")
    if not isinstance(attribute_allowlist, (list, tuple, set, frozenset)):
        raise ValueError("explicit directory attribute allowlist required")
    allowlist = frozenset(attribute_allowlist)
    for attribute in allowlist:
        identifier(attribute)
    # Validate/load the installed native core once, not per request or from an
    # untrusted import string. Every directory scope creates its own HTTPS client.
    core = PolicyCore(core_library)
    def directory_factory():
        client = HttpsJsonClient(ca_bundle=ca_bundle)
        try:
            return DirectoryProvider(directory_url, authorization=authorization,
                attribute_allowlist=allowlist, client=client,
                require_organization_ancestors=True)
        except Exception:
            client.session.close()
            raise
    resources = PolicyResources(environment=environment, redis=redis,
        provider_id=provider_id, directory_factory=directory_factory,
        native_schema=native_schema, identity_schema=identity_schema, prefix=prefix)
    return PolicyServiceFactory(authenticate=SeahubPolicyAuthentication(resources.state),
        preparation_scope=resources.preparation, core=core, cloud_mode=cloud_mode)
