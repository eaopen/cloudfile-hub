"""Bounded private tag binding enumeration; not content authorization.

Cursor is internal resource UID, not an exposed offset. Native lifecycle must
still be resolved before projection; concurrent bindings have their own events.
"""
from ..common.errors import ContractError
from ..resources.paths import resource_ref
from ..tags.definitions import decode, uuid_value
from ..tags.read import FIELDS


def binding_cutoff(cursor, *, tag_id):
    """Capture once and persist with the batch job, not once per page.

    UUID upper bound is a scan boundary, not a temporal membership snapshot.
    Later bindings are covered by their independently persisted resource events.
    """
    uuid_value(tag_id)
    try:
        cursor.execute("SELECT MAX(resource_uid) FROM cf_tag_binding FORCE INDEX(tag_resources) WHERE tag_id=%s", (tag_id,))
        row = cursor.fetchone()
        if row is None or len(row) != 1:
            raise ValueError()
        return None if row[0] is None else uuid_value(row[0])
    except Exception:
        raise ContractError("SEARCH_PROJECTION_PENDING", "Tag scan boundary is unavailable", 503) from None


def binding_page(cursor, *, repo_id, tag_id, revision, upper_uid, after=None, limit=100):
    uuid_value(repo_id)
    uuid_value(tag_id)
    uuid_value(revision)
    uuid_value(upper_uid)
    if after is not None:
        uuid_value(after)
        if after > upper_uid:
            raise ValueError("fanout cursor exceeds captured boundary")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("bounded fanout page required")
    try:
        cursor.execute("SELECT " + FIELDS + " FROM cf_tag WHERE tag_id=%s", (tag_id,))
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise ValueError()
        definition = decode(rows[0])
        if definition["revision"] != revision or definition["scope_repo_id"] not in (None, repo_id):
            raise ContractError("SEARCH_FANOUT_CHANGED", "Tag fanout source changed", 409)
        cursor.execute("SELECT column_name,sub_part FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_tag_binding' AND index_name='tag_resources' ORDER BY seq_in_index")
        if tuple(cursor.fetchall()) != (("tag_id", None), ("resource_uid", None)):
            raise ValueError()
        # Limit binding rows before projecting any metadata. Global system tags
        # may include other libraries; skipped rows still advance this scan.
        cursor.execute("SELECT b.resource_uid,r.uid,r.repo_id,r.path,r.kind,r.state FROM cf_tag_binding b FORCE INDEX(tag_resources) LEFT JOIN cf_resource r ON r.uid=b.resource_uid WHERE b.tag_id=%s AND b.resource_uid>%s AND b.resource_uid<=%s ORDER BY b.resource_uid LIMIT %s", (tag_id, after or "", upper_uid, limit + 1))
        rows = cursor.fetchall()
        if len(rows) > limit + 1:
            raise ValueError()
        selected, previous = [], after or ""
        for row in rows[:limit]:
            uid = uuid_value(row[0])
            if uid <= previous or uid > upper_uid or row[1] != uid:
                raise ValueError()
            previous = uid
            ref = resource_ref(dict(repo_id=row[2], path=row[3], kind=row[4]))
            if len(ref["path"].encode("utf-8")) > 4096:
                raise ValueError()
            if ref["repo_id"] != repo_id:
                if definition["scope_repo_id"] is not None:
                    raise ValueError()
                continue
            if row[5] != "active":
                raise ContractError("SEARCH_PROJECTION_PENDING", "Tag resource requires lifecycle reconciliation", 503)
            selected.append(dict(resource_uid=uid, reference=ref))
        return dict(items=selected, next_uid=previous if len(rows) > limit else None)
    except ContractError:
        raise
    except Exception:
        raise ContractError("SEARCH_PROJECTION_PENDING", "Tag binding source requires reconciliation", 503) from None
