"""Validate a coherent source snapshot before it is eligible for authorization."""

from datetime import datetime, timezone

from ..common.errors import invalid
from ..common.validation import identifier, object_fields, sequence, utc_time


def validate_subject(value, *, requested_user_id, attribute_allowlist,
                     now=None, maximum_clock_skew=60):
    object_fields(value, ("userId", "status", "attributes", "organizations", "roles",
                          "etag", "generated_at"), ("revision", "organization_revision", "organization_ancestors"))
    identifier(value["userId"], maximum=225)
    if value["userId"] != requested_user_id:
        raise invalid("Directory subject does not match requested identity")
    if value["status"] not in ("active", "disabled"):
        raise invalid("Invalid subject status")
    attributes = value["attributes"]
    if (not isinstance(attributes, dict) or len(attributes) > 32 or
            set(attributes) - set(attribute_allowlist) or
            any(not isinstance(key, str) or not (item is None or type(item) in (str, bool)) or
                (isinstance(item, str) and len(item) > 4096)
                for key, item in attributes.items())):
        raise invalid("Invalid or unsupported subject attributes")
    for field in ("revision", "organization_revision"):
        if field in value:
            sequence(value[field])
    identifier(value["etag"])
    generated = utc_time(value["generated_at"])
    now = datetime.now(timezone.utc) if now is None else now
    if generated.timestamp() > now.timestamp() + maximum_clock_skew:
        raise invalid("Directory timestamp is in the future")
    normalized = {}
    for field in ("organizations", "roles"):
        items = value[field]
        if not isinstance(items, list) or len(items) > 4096:
            raise invalid("Missing subject memberships")
        seen = set()
        normalized[field] = []
        for item in items:
            required = ("namespace", "external_id", "is_primary") if field == "organizations" else ("namespace", "external_id")
            object_fields(item, required)
            key = (identifier(item["namespace"]), identifier(item["external_id"]))
            if key in seen:
                raise invalid("Duplicate subject membership")
            if field == "organizations" and type(item["is_primary"]) is not bool:
                raise invalid("Invalid primary organization flag")
            seen.add(key)
            normalized[field].append(dict(item))
    if sum(item["is_primary"] for item in normalized["organizations"]) > 1:
        raise invalid("Multiple primary organizations")
    if "organization_ancestors" in value:
        ancestors = value["organization_ancestors"]
        if not isinstance(ancestors, list) or len(ancestors) + len(normalized["organizations"]) > 4096:
            raise invalid("Invalid effective organization memberships")
        seen = {(item["namespace"], item["external_id"]) for item in normalized["organizations"]}
        normalized["organization_ancestors"] = []
        for item in ancestors:
            object_fields(item, ("namespace", "external_id"))
            key = (identifier(item["namespace"]), identifier(item["external_id"]))
            if key in seen:
                raise invalid("Duplicate effective organization membership")
            seen.add(key)
            normalized["organization_ancestors"].append(dict(item))
        if value["status"] == "disabled" and ancestors:
            raise invalid("Disabled subject cannot have organization ancestors")
    return {**value, "attributes": dict(attributes), **normalized}
