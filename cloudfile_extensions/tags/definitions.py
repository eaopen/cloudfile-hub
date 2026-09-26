import re
import unicodedata
from uuid import UUID

from ..common.errors import invalid
from ..common.validation import identifier, object_fields


def uuid_value(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        raise invalid("Invalid tag identity") from None
    return value


def label_value(value):
    if not isinstance(value, str):
        raise invalid("Invalid tag label")
    value = unicodedata.normalize("NFC", value.strip())
    if (not 1 <= len(value) <= 64 or any(char in "<>" or unicodedata.category(char).startswith("C") for char in value)):
        raise invalid("Invalid tag label")
    return value


def color_value(value):
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
        raise invalid("Invalid tag color")
    return value.upper()


def user_definition(repo, tag_id, value):
    """Caller supplies trusted library identity; body cannot choose namespace."""
    uuid_value(repo)
    uuid_value(tag_id)
    object_fields(value, ("label",), ("color",))
    label = label_value(value["label"])
    return dict(tag_id=tag_id, kind="user", provider="cloudfile", namespace="user:" + repo,
        code=tag_id, label=label, normalized_label=label, color=color_value(value.get("color")),
        enabled=True, scope_repo_id=repo)


def decode(row):
    if len(row) != 11:
        raise ValueError("invalid stored tag")
    tag_id, kind, provider, namespace, code, label, normalized, color, enabled, repo, revision = row
    uuid_value(tag_id)
    uuid_value(revision)
    identifier(provider, maximum=32)
    identifier(namespace)
    identifier(code, maximum=128)
    if label_value(label) != label or color_value(color) != color or type(enabled) is not int or enabled not in (0, 1):
        raise ValueError("invalid stored tag value")
    if repo is not None:
        uuid_value(repo)
    if kind == "user":
        if repo is None or provider != "cloudfile" or namespace != "user:" + repo or code != tag_id or normalized != label:
            raise ValueError("invalid user tag scope")
    elif kind != "system" or namespace.startswith("user:") or normalized is not None:
        raise ValueError("invalid system tag scope")
    return dict(tag_id=tag_id, kind=kind, provider=provider, namespace=namespace,
        code=code, label=label, color=color, enabled=bool(enabled), scope_repo_id=repo,
        revision=revision, etag='"' + revision + '"')
