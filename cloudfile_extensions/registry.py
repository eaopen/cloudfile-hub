"""Trusted implementation registration, separate from deployment requests."""

from dataclasses import dataclass
from types import MappingProxyType
import re


RESERVED_DOMAINS = frozenset({
    "directory", "authorization", "library-policy", "directory-acl",
    "annotations", "audit", "search", "locks", "editing", "local-edit", "migration", "transfer", "identity",
})
CAPABILITY_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


@dataclass(frozen=True)
class CapabilityImplementation:
    version: str
    implemented: bool = False
    provider: str = ""
    dependencies: tuple = ()
    default_enabled: bool = False


BUILTIN_IMPLEMENTATIONS = MappingProxyType({
    "extension.contract": CapabilityImplementation("1.0", True, default_enabled=True),
    "auth.basic": CapabilityImplementation("14", True, default_enabled=True),
    "protocol.webdav": CapabilityImplementation("14", True),
    "auth.oidc": CapabilityImplementation("1", provider="authentik"),
    "directory.subjects": CapabilityImplementation("1", dependencies=("auth.oidc",)),
    "directory.groups.manage": CapabilityImplementation("1", dependencies=("auth.basic",)),
    "authorization.refresh": CapabilityImplementation("1", dependencies=("directory.subjects",)),
    "library.policy": CapabilityImplementation("1", dependencies=("directory.subjects",)),
    "directory.acl": CapabilityImplementation("1", dependencies=("library.policy",)),
    "directory.acl.effective": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "directory.acl.manage": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "library.shares.manage": CapabilityImplementation("1", dependencies=("auth.basic",)),
    "library.admin.manage": CapabilityImplementation("1", True, dependencies=("auth.basic",), default_enabled=True),
    "library.config.manage": CapabilityImplementation("1", True, dependencies=("auth.basic",), default_enabled=True),
    "library.admin.revoke": CapabilityImplementation("1", True, dependencies=("auth.basic",), default_enabled=True),
    "transfer.web": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "audit.log": CapabilityImplementation("1"),
    # Query transport readiness is narrower than complete audit source coverage.
    "audit.query": CapabilityImplementation("1"),
    "resource.description": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "resource.local-open-type": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "tag.extended": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "search.resources": CapabilityImplementation("1", provider="meilisearch", dependencies=("directory.acl", "tag.extended")),
    "file.lock": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "local.open-edit": CapabilityImplementation("1", dependencies=("directory.acl",)),
    "migration.local-import": CapabilityImplementation("1", dependencies=("audit.log",)),
    "search.fulltext": CapabilityImplementation("1", dependencies=("search.resources",)),
    "storage.s3": CapabilityImplementation("1"),
    "federation": CapabilityImplementation("1"),
})


class ImplementationRegistry:
    """Only installed Python code can register an implementation, not settings JSON."""

    def __init__(self):
        self._implementations = dict(BUILTIN_IMPLEMENTATIONS)

    @property
    def implementations(self):
        return MappingProxyType(self._implementations)

    def register_extension(self, namespace, name, implementation):
        if (not isinstance(namespace, str) or
                not re.fullmatch(r"[a-z][a-z0-9-]*", namespace) or
                namespace in RESERVED_DOMAINS or namespace in {"auth", "extension"}):
            raise ValueError("invalid or reserved extension namespace")
        if (not isinstance(name, str) or not CAPABILITY_NAME_RE.fullmatch(name) or
                not name.startswith(namespace + ".")):
            raise ValueError("capability must belong to its extension namespace")
        if name in self._implementations:
            raise ValueError("capability implementation is already registered")
        if not isinstance(implementation, CapabilityImplementation):
            raise ValueError("invalid capability implementation")
        if (not isinstance(implementation.version, str) or not implementation.version or
                type(implementation.implemented) is not bool or
                type(implementation.default_enabled) is not bool or
                not isinstance(implementation.provider, str) or
                not isinstance(implementation.dependencies, tuple) or
                any(not isinstance(dep, str) or not CAPABILITY_NAME_RE.fullmatch(dep)
                    for dep in implementation.dependencies)):
            raise ValueError("invalid capability implementation fields")
        self._implementations[name] = implementation


registry = ImplementationRegistry()
