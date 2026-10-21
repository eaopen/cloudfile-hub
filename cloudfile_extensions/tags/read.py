"""Bound-resource reads, never an unfiltered whole-library dictionary."""
from copy import deepcopy

from ..common.errors import ContractError
from .definitions import decode, uuid_value


FIELDS = "tag_id,kind,provider,namespace,code,label,normalized_label,color,enabled,scope_repo_id,revision"


def _storage(cursor):
    # Share the existing schema/engine checks without weakening either reader.
    for table, primary in (("cf_tag_binding", "resource_uid,tag_id"), ("cf_tag", "tag_id")):
        cursor.execute("SELECT * FROM " + table + " LIMIT 0 FOR UPDATE")
        cursor.fetchall()
        cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
        if cursor.fetchall() != (("InnoDB",),):
            raise ValueError("unsafe tag storage")
        cursor.execute("SELECT GROUP_CONCAT(column_name ORDER BY seq_in_index) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=%s AND index_name='PRIMARY' AND non_unique=0 AND sub_part IS NULL", (table,))
        if cursor.fetchall() != ((primary,),):
            raise ValueError("invalid tag primary index")


def bound_tags(cursor, *, resource_uid, repo_id):
    """Trusted caller already holds content/UID lifecycle authority transaction."""
    uuid_value(resource_uid)
    uuid_value(repo_id)
    try:
        _storage(cursor)
        cursor.execute("SELECT tag_id FROM cf_tag_binding WHERE resource_uid=%s ORDER BY tag_id LIMIT 129 FOR UPDATE", (resource_uid,))
        ids = [uuid_value(row[0]) for row in cursor.fetchall()]
        if len(ids) > 128 or len(ids) != len(set(ids)):
            raise ValueError("resource tag budget exceeded")
        if not ids:
            return []
        cursor.execute("SELECT " + FIELDS + " FROM cf_tag WHERE tag_id IN (" + ",".join(["%s"] * len(ids)) + ") ORDER BY tag_id FOR UPDATE", tuple(ids))
        values = [decode(row) for row in cursor.fetchall()]
        if {value["tag_id"] for value in values} != set(ids) or len(values) != len(ids):
            raise ValueError("orphan resource tags")
        if any(value["scope_repo_id"] not in (None, repo_id) for value in values):
            raise ValueError("foreign library tag binding")
        return sorted(values, key=lambda value: (value["kind"] != "system", value["label"], value["tag_id"]))
    except Exception:
        raise ContractError("TAGS_UNAVAILABLE", "Resource tags require reconciliation", 503) from None


def bound_tags_many(cursor, *, resources):
    """UID -> structured tags inside the caller's authorized transaction.

    Bounded bindings and their referenced definitions only; no legacy tags or
    dictionary scan. Sharing a definition never shares a resource permission.
    """
    if not isinstance(resources, dict) or len(resources) > 50:
        raise ValueError("bounded resource UID to repository mapping required")
    for uid, repo in resources.items():
        uuid_value(uid)
        uuid_value(repo)
    if not resources:
        return {}
    try:
        _storage(cursor)
        uids = sorted(resources)
        cursor.execute("SELECT resource_uid,tag_id FROM cf_tag_binding WHERE resource_uid IN (" +
            ",".join(["%s"] * len(uids)) + ") ORDER BY resource_uid,tag_id LIMIT " +
            str(128 * len(uids) + 1) + " FOR UPDATE", tuple(uids))
        bindings = {uid: set() for uid in uids}
        for uid, tag_id in cursor.fetchall():
            uuid_value(tag_id)
            if uid not in bindings or tag_id in bindings[uid] or len(bindings[uid]) >= 128:
                raise ValueError("resource tag budget exceeded")
            bindings[uid].add(tag_id)
        ids = sorted(set().union(*bindings.values()))
        if not ids:
            return {uid: [] for uid in uids}
        # Fifty resources * 128 tags bounds both parameters and definition rows.
        cursor.execute("SELECT " + FIELDS + " FROM cf_tag WHERE tag_id IN (" +
            ",".join(["%s"] * len(ids)) + ") ORDER BY tag_id LIMIT " + str(len(ids) + 1) +
            " FOR UPDATE", tuple(ids))
        values = [decode(row) for row in cursor.fetchall()]
        definitions = {value["tag_id"]: value for value in values}
        if set(definitions) != set(ids) or len(values) != len(ids):
            raise ValueError("orphan resource tags")
        result = {}
        for uid, bound in bindings.items():
            # Query definitions once, but isolate each resource's returned DTO,
            # including nested values, from other resources and loaded inputs.
            tags = [deepcopy(definitions[tag_id]) for tag_id in bound]
            if any(value["scope_repo_id"] not in (None, resources[uid]) for value in tags):
                raise ValueError("foreign library tag binding")
            result[uid] = sorted(tags, key=lambda value: (value["kind"] != "system", value["label"], value["tag_id"]))
        return result
    except Exception:
        raise ContractError("TAGS_UNAVAILABLE", "Resource tags require reconciliation", 503) from None
