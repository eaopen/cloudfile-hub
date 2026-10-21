"""Atomic user-tag replacement on an already-resolved sparse resource UID.

Caller owns actual content-write/lifecycle scope and SQL transaction. No public
grant, first-use UID allocation, system namespace write or transaction commit.
"""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.errors import ContractError, invalid
from ..events.outbox import EventWriter
from ..common.validation import identifier
from ..resources.paths import resource_ref
from .definitions import decode, uuid_value
from .read import bound_tags, FIELDS


def replace_user_tags(cursor, *, reference, resource_uid, lifecycle_ref,
                      expected_revision, tag_ids, actor, request_id):
    return _replace(cursor, reference=reference, resource_uid=resource_uid,
        lifecycle_ref=lifecycle_ref, expected_revision=expected_revision,
        tag_ids=tag_ids, actor=actor, request_id=request_id, source=None)


def replace_system_tags(cursor, *, reference, resource_uid, lifecycle_ref,
                        expected_revision, tag_ids, actor, request_id,
                        provider, namespace, authorize_namespace):
    """Trusted service's exact source scope; callback must lock real authority.

    No browser-provided source claim or boolean configuration is a grant.
    Caller additionally holds actual content-write/lifecycle authority.
    """
    identifier(provider, maximum=32)
    identifier(namespace)
    if namespace.startswith("user:") or not callable(authorize_namespace):
        raise invalid("Invalid system tag source")
    ref = resource_ref(reference)
    if authorize_namespace(cursor, actor, ref, provider, namespace) is not True:
        raise ContractError("ACCESS_DENIED", "System tag namespace is not allowed", 403)
    return _replace(cursor, reference=ref, resource_uid=resource_uid,
        lifecycle_ref=lifecycle_ref, expected_revision=expected_revision,
        tag_ids=tag_ids, actor=actor, request_id=request_id, source=(provider, namespace))


def _replace(cursor, *, reference, resource_uid, lifecycle_ref,
             expected_revision, tag_ids, actor, request_id, source):
    ref = resource_ref(reference)
    uuid_value(resource_uid)
    if type(expected_revision) is not int or not 1 <= expected_revision < 2 ** 64 - 1:
        raise invalid("Invalid internal resource revision")
    if not isinstance(tag_ids, list) or len(tag_ids) > 128:
        raise invalid("Too many resource tags")
    ids = [uuid_value(item) for item in tag_ids]
    if len(ids) != len(set(ids)):
        raise invalid("Duplicate resource tags")
    cursor.execute("SELECT repo_id,path,kind,lifecycle_ref,revision,state FROM cf_resource WHERE uid=%s FOR UPDATE", (resource_uid,))
    rows = cursor.fetchall()
    cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_resource'")
    if cursor.fetchall() != (("InnoDB",),):
        raise ContractError("PATH_STATE_PENDING", "Resource storage requires reconciliation", 503)
    if len(rows) != 1 or rows[0][:4] != (ref["repo_id"], ref["path"], ref["kind"], lifecycle_ref) or rows[0][5] != "active":
        raise ContractError("PATH_STATE_PENDING", "Resource lifecycle requires reconciliation", 503)
    if rows[0][4] != expected_revision:
        raise ContractError("RESOURCE_REVISION_CONFLICT", "Resource has changed", 409)
    old = bound_tags(cursor, resource_uid=resource_uid, repo_id=ref["repo_id"])
    def selected(tag):
        return (tag["kind"] == "user" if source is None else
                tag["kind"] == "system" and (tag["provider"], tag["namespace"]) == source)
    previous = {tag["tag_id"] for tag in old if selected(tag)}
    preserved_count = len(old) - len(previous)
    if preserved_count + len(ids) > 128:
        raise invalid("Too many resource tags")
    if ids:
        cursor.execute("SELECT " + FIELDS + " FROM cf_tag WHERE tag_id IN (" + ",".join(["%s"] * len(ids)) + ") ORDER BY tag_id FOR UPDATE", tuple(sorted(ids)))
        definitions = [decode(row) for row in cursor.fetchall()]
        if len(definitions) != len(ids) or {tag["tag_id"] for tag in definitions} != set(ids):
            raise ContractError("NOT_FOUND", "Tag is not available", 404)
        if any(not selected(tag) or tag["scope_repo_id"] not in
               ((ref["repo_id"],) if source is None else (None, ref["repo_id"])) for tag in definitions):
            raise ContractError("NOT_FOUND", "Tag is not available", 404)
        if any(not tag["enabled"] and tag["tag_id"] not in previous for tag in definitions):
            raise ContractError("TAG_DISABLED", "New binding to a disabled tag is not allowed", 409)
    target = set(ids)
    if target == previous:
        return expected_revision, False
    for tag_id in sorted(previous - target):
        cursor.execute("DELETE FROM cf_tag_binding WHERE resource_uid=%s AND tag_id=%s", (resource_uid, tag_id))
        if cursor.rowcount != 1:
            raise ContractError("TAGS_UNAVAILABLE", "Tag bindings require reconciliation", 503)
    for tag_id in sorted(target - previous):
        cursor.execute("INSERT INTO cf_tag_binding(resource_uid,tag_id) VALUES(%s,%s)", (resource_uid, tag_id))
    cursor.execute("UPDATE cf_resource SET revision=revision+1,updated_at=UTC_TIMESTAMP(6) WHERE uid=%s AND revision=%s", (resource_uid, expected_revision))
    if cursor.rowcount != 1:
        raise ContractError("RESOURCE_REVISION_CONFLICT", "Resource has changed", 409)
    revision = expected_revision + 1
    EventWriter().append(cursor, dict(event_id=str(uuid4()), request_id=request_id,
        occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        actor_user_id=actor, actor_kind="user" if source is None else "service", source="hub", action="tags.bindings.updated",
        result="succeeded", repo_id=ref["repo_id"], path=ref["path"], resource_uid=resource_uid,
        revision=str(revision)))
    return revision, True
