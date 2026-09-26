"""Keep decoded JSON names intact; decode URL transport exactly once."""

import re
from urllib.parse import unquote_plus
from uuid import UUID

from ..common.errors import ContractError, invalid
from ..common.validation import object_fields


def normalize_path(path, kind, *, transport="json"):
    error = ContractError("INVALID_PATH", "Invalid resource path")
    if not isinstance(path, str) or kind not in ("file", "dir"):
        raise error
    if transport == "url_query_raw":
        if re.search(r"%(?![0-9A-Fa-f]{2})", path):
            raise error
        try:
            path = unquote_plus(path, encoding="utf-8", errors="strict")
        except UnicodeError:
            raise error from None
    elif transport != "json":
        raise invalid("Unknown path transport")
    if not path.startswith("/") or "\x00" in path or "//" in path:
        raise error
    if path.endswith("/") and path != "/":
        if kind == "file":
            raise error
        path = path[:-1]
    if path == "/" and kind == "file":
        raise error
    if any(segment in (".", "..") for segment in path.split("/")):
        raise error
    return path


def is_descendant_or_equal(path, ancestor):
    return path == ancestor or ancestor == "/" or path.startswith(ancestor + "/")


def resource_ref(value):
    object_fields(value, ("repo_id", "path", "kind"))
    if not isinstance(value["repo_id"], str):
        raise invalid("Invalid repository ID")
    try:
        repo = str(UUID(value["repo_id"]))
    except (ValueError, AttributeError):
        raise invalid("Invalid repository ID") from None
    return {"repo_id": repo, "path": normalize_path(value["path"], value["kind"]), "kind": value["kind"]}
