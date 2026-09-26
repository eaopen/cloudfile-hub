"""Build the public, project-neutral CloudFile capability document."""

from __future__ import annotations

import re
import logging
from collections.abc import Mapping

from . import __version__
from .registry import registry


CONTRACT_VERSION = "1.0"
CAPABILITY_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
PUBLIC_CAPABILITY_FIELDS = ("enabled", "version", "provider")
logger = logging.getLogger(__name__)


def _normalize_capability(name, value):
    if not isinstance(name, str) or not CAPABILITY_NAME_RE.fullmatch(name):
        raise ValueError(f"invalid capability name: {name!r}")

    if isinstance(value, bool):
        return {"enabled": value}
    if not isinstance(value, Mapping):
        raise ValueError(f"capability {name!r} must be a boolean or mapping")

    unknown_fields = set(value) - set(PUBLIC_CAPABILITY_FIELDS)
    if unknown_fields:
        fields = ", ".join(sorted(unknown_fields))
        raise ValueError(f"capability {name!r} has unsupported public fields: {fields}")

    normalized = {field: value[field] for field in PUBLIC_CAPABILITY_FIELDS if field in value}
    enabled = normalized.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError(f"capability {name!r} enabled must be a boolean")
    normalized["enabled"] = enabled

    for field in ("version", "provider"):
        field_value = normalized.get(field)
        if field in normalized and not isinstance(field_value, str):
            raise ValueError(f"capability {name!r} {field} must be a string")

    return normalized


def build_capability_document(configured=None, *, seafile_version="14.0.8",
                              implementation_registry=None, webdav_enabled=False):
    """Configuration can disable/request features, never manufacture their implementation."""
    if type(webdav_enabled) is not bool:
        raise ValueError("WebDAV integration flag must be a boolean")
    capabilities = {}
    if configured is not None:
        if not isinstance(configured, Mapping):
            raise ValueError("CLOUDFILE_CAPABILITIES must be a mapping")
        capabilities.update(configured)

    requested = {
        name: _normalize_capability(name, value)
        for name, value in sorted(capabilities.items())
    }
    implementations = (registry if implementation_registry is None
                       else implementation_registry).implementations
    resolved = {}
    visiting = set()

    def resolve(name):
        if name in resolved:
            return resolved[name]["enabled"]
        if name in visiting:
            raise ValueError("cyclic capability dependencies")
        implementation = implementations.get(name)
        config = requested.get(name, {})
        if implementation is None:
            # Log only validated names, not arbitrary deployment values or secrets.
            logger.warning("CloudFile capability is not registered: %s", name)
            resolved[name] = {"enabled": False}
            return False
        visiting.add(name)
        enabled = implementation.implemented and config.get(
            "enabled", implementation.default_enabled
        )
        if name == "protocol.webdav":
            enabled = enabled and webdav_enabled
        if config.get("version", implementation.version) != implementation.version:
            enabled = False
        if config.get("provider", implementation.provider) != implementation.provider:
            enabled = False
        dependency_results = [resolve(dep) for dep in implementation.dependencies]
        enabled = bool(enabled and all(dependency_results))
        if config.get("enabled", False) and not enabled:
            logger.warning("CloudFile capability request is not available: %s", name)
        value = {"enabled": enabled, "version": implementation.version}
        if implementation.provider:
            value["provider"] = implementation.provider
        resolved[name] = value
        visiting.remove(name)
        return enabled

    for name in sorted(set(implementations) | set(requested)):
        resolve(name)
    normalized = {name: resolved[name] for name in sorted(resolved)}
    return {
        "product": "CloudFile",
        "version": __version__,
        "seafile_version": str(seafile_version),
        "contract_version": CONTRACT_VERSION,
        "capabilities": normalized,
    }
