"""Immutable per-Intent CloudFile CDC plan, never a general Seafile upload right.

Native Seafile CDC metadata is ordered SHA-1 block IDs plus total file size.
A plan is bound to the already prepared, device-signed CommitIntent. File
publication is forbidden until the native guarded Branch transaction checks
the same current account, lease, file baseline and durable receipt again.
"""
import hashlib
import json
import re
import time

from ..common.errors import ContractError

MAX_BLOCK = 10 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024  # P0; lift separately after measured large-file E2E.
MAX_BLOCKS = 64
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def validate_plan(value, grant):
    if not isinstance(value, dict) or set(value) != {"file_id", "size", "sha256", "blocks"}:
        raise ValueError("Exact CDC plan required")
    size, blocks = value["size"], value["blocks"]
    if (type(size) is not int or size < 1 or size > MAX_FILE or
            size != grant["snapshot_size"] or value["sha256"] != grant["content_digest"] or
            not isinstance(value["sha256"], str) or not HEX64.fullmatch(value["sha256"]) or
            not isinstance(blocks, list) or not 1 <= len(blocks) <= MAX_BLOCKS):
        raise ValueError("Bounded sealed CDC content required")
    ordered, sizes, total = [], {}, 0
    for item in blocks:
        if not isinstance(item, dict) or set(item) != {"id", "size"}:
            raise ValueError("Exact CDC block required")
        block_id, block_size = item["id"], item["size"]
        if (not isinstance(block_id, str) or not HEX40.fullmatch(block_id) or
                type(block_size) is not int or not 1 <= block_size <= MAX_BLOCK):
            raise ValueError("Invalid CDC block identity or size")
        if block_id in sizes and sizes[block_id] != block_size:
            raise ValueError("Contradictory repeated block size")
        sizes[block_id] = block_size
        total += block_size
        ordered.append(block_id)
    if total != size:
        raise ValueError("CDC ordered blocks do not cover the committed bytes")
    # Matches Seafile Jansson JSON_SORT_KEYS for version 1 and Go FileObjectID.
    native_json = json.dumps({"block_ids": ordered, "size": size, "type": 1,
                              "version": 1}, sort_keys=True, ensure_ascii=True)
    file_id = hashlib.sha1(native_json.encode("ascii")).hexdigest()
    if value["file_id"] != file_id:
        raise ValueError("Seafile native File ID does not match ordered blocks")
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")), ordered, sizes


def columns(grant):
    condition = grant["condition"]
    if "agent_upload" in condition:
        session = condition["agent_upload"]
        return (session["intent_id"],session["session_id"],session["device_id"],
                grant["repo_id"],grant["snapshot_size"],grant["content_digest"])
    edit = condition["editing"]
    session = condition["local_commit"]
    return (edit["intent_id"], session["session_id"], session["device_id"],
            edit["repo_id"], grant["snapshot_size"], grant["content_digest"])


class BlockPlanStore:
    def load(self, sql, grant):
        identity = columns(grant)
        sql.execute("SELECT session_id,device_id,repo_id,file_size,content_digest,"
                    "manifest_json,expires_at FROM cf_device_block_plan "
                    "WHERE intent_id=%s FOR UPDATE", (identity[0],))
        row = sql.fetchone()
        if not row or tuple(row[:5]) != identity[1:] or int(row[6]) <= int(time.time()):
            raise ContractError("EDIT_CONFLICT", "Current device CDC plan unavailable", 409)
        data = json.loads(row[5])
        encoded, ordered, sizes = validate_plan(data, grant)
        if row[5] != encoded:
            raise ContractError("EDIT_CONFLICT", "Persisted CDC plan mismatch", 409)
        return data, ordered, sizes

    def create(self, sql, grant, value):
        encoded, ordered, sizes = validate_plan(value, grant)
        identity = columns(grant)
        # Immutable value keyed by the original server-prepared Intent. A retry
        # may only use the exact same file identity and ordered block manifest.
        sql.execute("INSERT INTO cf_device_block_plan"
                    "(intent_id,session_id,device_id,repo_id,file_size,"
                    "content_digest,manifest_json,expires_at,created_at)"
                    " VALUES(%s,%s,%s,%s,%s,%s,%s,"
                    "FLOOR(UNIX_TIMESTAMP())+3600,UTC_TIMESTAMP(6)) "
                    "ON DUPLICATE KEY UPDATE intent_id=intent_id",
                    (*identity, encoded))
        existing, ordered, sizes = self.load(sql, grant)
        if existing != value:
            raise ContractError("EDIT_CONFLICT", "Original CDC plan cannot change", 409)
        return ordered, sizes
