"""Build the public, project-neutral CloudFile capability document."""

from __future__ import annotations

import re
from collections.abc import Mapping

from . import __version__


CONTRACT_VERSION = "1.0"
CAPABILITY_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
BASE_CAPABILITIES = {
    "extension.contract": {
        "enabled": True,
        "version": CONTRACT_VERSION,
    },
}
PUBLIC_CAPABILITY_FIELDS = ("enabled", "version", "provider")


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
        if field_value is not None and not isinstance(field_value, str):
            raise ValueError(f"capability {name!r} {field} must be a string")

    return normalized


def build_capability_document(configured=None, *, seafile_version="14.0.8"):
    capabilities = dict(BASE_CAPABILITIES)
    if configured is not None:
        if not isinstance(configured, Mapping):
            raise ValueError("CLOUDFILE_CAPABILITIES must be a mapping")
        capabilities.update(configured)

    normalized = {
        name: _normalize_capability(name, value)
        for name, value in sorted(capabilities.items())
    }
    return {
        "product": "CloudFile",
        "version": __version__,
        "seafile_version": str(seafile_version),
        "contract_version": CONTRACT_VERSION,
        "capabilities": normalized,
    }
