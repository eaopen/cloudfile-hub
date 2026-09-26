"""Transactional policy retry records, never an authentication credential."""
import json
from uuid import UUID


def require_storage(cursor):
    # Pin metadata before inspecting its shape; never trust migration presence
    # to prove a formerly altered table is transactional or uniquely indexed.
    cursor.execute("SELECT request_key FROM cf_policy_request LIMIT 0 FOR UPDATE")
    cursor.fetchall()
    cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_policy_request'")
    if cursor.fetchall() != (("InnoDB",),):
        raise ValueError("unsafe policy request storage")
    cursor.execute("SELECT column_name,data_type,character_octet_length,collation_name,is_nullable FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='cf_policy_request'")
    columns = {row[0]: row[1:] for row in cursor.fetchall()}
    expected = {"request_key": ("char", 64, "ascii_bin", "NO"),
                "request_digest": ("char", 64, "ascii_bin", "NO"),
                "result_json": ("text", 65535, "utf8mb4_bin", "NO"),
                "inherited_effect": ("tinyint", None, None, "NO"),
                "created_at": ("datetime", None, None, "NO")}
    if columns != expected:
        raise ValueError("invalid policy request columns")
    cursor.execute("SELECT column_name,seq_in_index,sub_part,non_unique FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_policy_request' AND index_name='PRIMARY' ORDER BY seq_in_index")
    if cursor.fetchall() != (("request_key", 1, None, 0),):
        raise ValueError("invalid policy request primary key")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate saved response field")
        result[key] = value
    return result


def response(text, *, reference, value, rule_id, validate):
    if not isinstance(text, str) or len(text.encode()) > 16384:
        raise ValueError("invalid saved policy response")
    result = json.loads(text, object_pairs_hook=_pairs)
    if not isinstance(result, dict):
        raise ValueError("invalid saved policy response")
    if value is None:
        if result != dict(id=rule_id, deleted=True) or type(result["deleted"]) is not bool:
            raise ValueError("invalid saved deletion")
        return result
    if set(result) != {"id", "repo_id", "path", "kind", "subject", "permission", "inherit", "revision", "etag"}:
        raise ValueError("invalid saved mutation fields")
    for key in ("id", "revision"):
        if str(UUID(result[key])) != result[key]:
            raise ValueError("invalid saved mutation identifier")
    if rule_id is not None and result["id"] != rule_id:
        raise ValueError("invalid saved rule identity")
    if result["etag"] != '"' + result["revision"] + '"' or result["repo_id"] != reference["repo_id"]:
        raise ValueError("invalid saved mutation revision")
    saved = validate({key: result[key] for key in ("path", "kind", "subject", "permission", "inherit")})
    if saved != value:
        raise ValueError("invalid saved mutation value")
    return result
