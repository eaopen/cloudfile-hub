"""Explicit protocol validation; credentials and authorization are handled elsewhere."""

import re
from datetime import datetime, timezone

from .errors import invalid


def object_fields(value, required, optional=()):
    if not isinstance(value, dict):
        raise invalid("Expected an object")
    if set(value) - (set(required) | set(optional)):
        raise invalid("Unsupported fields")
    if set(required) - set(value):
        raise invalid("Missing required fields")
    return value


def identifier(value, *, maximum=255):
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise invalid("Invalid identifier")
    return value


def sequence(value):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise invalid("Invalid source revision")
    # Bound adversarial big-integer parsing while retaining more range than SQL BIGINT.
    if len(value) > 128:
        raise invalid("Source revision is too large")
    return int(value)


def utc_time(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value):
        raise invalid("Expected UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise invalid("Invalid timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise invalid("Expected UTC timestamp")
    return parsed


def annotation_changes(value, *, kind):
    object_fields(value, (), ("description", "local_open_type"))
    if not value:
        raise invalid("No changes supplied")
    if "description" in value:
        if not isinstance(value["description"], str) or len(value["description"]) > 4096:
            raise invalid("Invalid description")
    if "local_open_type" in value:
        hint = value["local_open_type"]
        if (kind != "file" or not isinstance(hint, str) or len(hint) > 64 or
                not re.fullmatch(r"[A-Za-z0-9._-]*", hint)):
            raise invalid("Invalid local open type")
    return dict(value)
