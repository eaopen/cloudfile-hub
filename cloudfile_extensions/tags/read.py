"""Bound-resource reads, never an unfiltered whole-library dictionary."""
from ..common.errors import ContractError
from .definitions import decode, uuid_value


FIELDS = "tag_id,kind,provider,namespace,code,label,normalized_label,color,enabled,scope_repo_id,revision"


def bound_tags(cursor, *, resource_uid, repo_id):
    """Trusted caller already holds content/UID lifecycle authority transaction."""
    uuid_value(resource_uid)
    uuid_value(repo_id)
    try:
        for table, primary in (("cf_tag_binding", "resource_uid,tag_id"), ("cf_tag", "tag_id")):
            cursor.execute("SELECT * FROM " + table + " LIMIT 0 FOR UPDATE")
            cursor.fetchall()
            cursor.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            if cursor.fetchall() != (("InnoDB",),):
                raise ValueError("unsafe tag storage")
            cursor.execute("SELECT GROUP_CONCAT(column_name ORDER BY seq_in_index) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=%s AND index_name='PRIMARY' AND non_unique=0 AND sub_part IS NULL", (table,))
            if cursor.fetchall() != ((primary,),):
                raise ValueError("invalid tag primary index")
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
