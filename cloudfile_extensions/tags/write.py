"""Tag definition SQL primitives inside the caller's authority transaction.

No transaction starts/commits here. Caller must hold actual library management
authority for definition patches and resource write authority for create/bind.
"""
from datetime import datetime, timezone
from uuid import uuid4

from ..common.conditions import compare_if_match
from ..common.errors import ContractError
from ..events.outbox import EventWriter
from .definitions import user_definition, definition_changes, decode, uuid_value
from .read import FIELDS


def _storage(cursor):
    cursor.execute("SELECT tag_id FROM cf_tag LIMIT 0 FOR UPDATE")
    cursor.fetchall()
    cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_tag'")
    if cursor.fetchall() != (("InnoDB",),):
        raise ContractError("TAGS_UNAVAILABLE", "Tag storage requires reconciliation", 503)
    for index, columns in (("tag_user_label", "scope_repo_id,normalized_label"), ("tag_identity", "namespace,code"), ("PRIMARY", "tag_id")):
        cursor.execute("SELECT GROUP_CONCAT(column_name ORDER BY seq_in_index) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_tag' AND index_name=%s AND non_unique=0 AND sub_part IS NULL", (index,))
        if cursor.fetchall() != ((columns,),):
            raise ContractError("TAGS_UNAVAILABLE", "Tag indexes require reconciliation", 503)


def _event(cursor, value, actor, request_id, action):
    EventWriter().append(cursor, dict(event_id=str(uuid4()), request_id=request_id,
        occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        actor_user_id=actor, actor_kind="user", source="hub", action=action,
        result="succeeded", repo_id=value["scope_repo_id"], revision=value["revision"],
        reason="tag_id:" + value["tag_id"]))


def create_user(cursor, *, repo_id, value, actor, request_id):
    candidate = user_definition(repo_id, str(uuid4()), value)
    _storage(cursor)
    cursor.execute("SELECT " + FIELDS + " FROM cf_tag FORCE INDEX (tag_user_label) WHERE scope_repo_id=%s AND normalized_label=%s LIMIT 2 FOR UPDATE", (repo_id, candidate["normalized_label"]))
    rows = cursor.fetchall()
    if len(rows) > 1:
        raise ContractError("TAGS_UNAVAILABLE", "Tag identity requires reconciliation", 503)
    if rows:
        existing = decode(rows[0])
        if existing["kind"] != "user" or existing["scope_repo_id"] != repo_id or existing["label"] != candidate["label"]:
            raise ContractError("TAGS_UNAVAILABLE", "Tag identity requires reconciliation", 503)
        if not existing["enabled"]:
            raise ContractError("TAG_DISABLED", "Existing tag is disabled", 409)
        # Existing definition/color wins; retries never silently mutate it.
        return existing, False
    revision = str(uuid4())
    row = (candidate["tag_id"], "user", "cloudfile", candidate["namespace"], candidate["code"],
        candidate["label"], candidate["normalized_label"], candidate["color"], 1, repo_id, revision)
    cursor.execute("INSERT INTO cf_tag(" + FIELDS + ",updated_at) VALUES(" + ",".join(["%s"] * 11) + ",UTC_TIMESTAMP(6))", row)
    result = decode(row)
    _event(cursor, result, actor, request_id, "tags.definition.created")
    return result, True


def patch_user(cursor, *, repo_id, tag_id, changes, if_match, actor, request_id):
    uuid_value(repo_id)
    uuid_value(tag_id)
    changes = definition_changes(changes)
    _storage(cursor)
    cursor.execute("SELECT " + FIELDS + " FROM cf_tag WHERE tag_id=%s FOR UPDATE", (tag_id,))
    rows = cursor.fetchall()
    if len(rows) != 1:
        raise ContractError("NOT_FOUND", "Tag is not available", 404)
    old = decode(rows[0])
    if old["kind"] != "user" or old["scope_repo_id"] != repo_id:
        raise ContractError("NOT_FOUND", "Tag is not available", 404)
    compare_if_match(if_match, old["etag"])
    target = {**old, **changes}
    if all(target[key] == old[key] for key in ("label", "color", "enabled")):
        return old, False
    revision = str(uuid4())
    cursor.execute("UPDATE cf_tag SET label=%s,normalized_label=%s,color=%s,enabled=%s,revision=%s,updated_at=UTC_TIMESTAMP(6) WHERE tag_id=%s AND revision=%s",
        (target["label"], target["label"], target["color"], int(target["enabled"]), revision, tag_id, old["revision"]))
    if cursor.rowcount != 1:
        raise ContractError("PRECONDITION_FAILED", "Tag has changed", 412)
    result = {**target, "revision": revision, "etag": '"' + revision + '"'}
    _event(cursor, result, actor, request_id, "tags.definition.updated")
    return result, True
