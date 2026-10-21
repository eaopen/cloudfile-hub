"""Bounded user dictionary consumption under whole-library management."""
from ..common.errors import ContractError, invalid
from .definitions import uuid_value, decode
from .read import FIELDS
from .write import _storage


def list_user_definitions(cursor, *, repo_id, limit=50, after=None):
    """Caller owns current management authority and transaction on this cursor.

    Live keyset pages, not a frozen export. No count, resource join or system
    namespace enumeration. Disabled definitions remain available to managers.
    """
    uuid_value(repo_id)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise invalid("Invalid tag page size")
    if after is not None:
        uuid_value(after)
    _storage(cursor)
    cursor.execute("SELECT column_name,non_unique,sub_part FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_tag' AND index_name='tag_scope' ORDER BY seq_in_index")
    if cursor.fetchall() != (("scope_repo_id", 1, None), ("kind", 1, None), ("tag_id", 1, None)):
        raise ContractError("TAGS_UNAVAILABLE", "Tag dictionary index requires reconciliation", 503)
    if after is not None:
        cursor.execute("SELECT " + FIELDS + " FROM cf_tag WHERE tag_id=%s FOR UPDATE", (after,))
        rows = cursor.fetchall()
        if len(rows) != 1:
            raise ContractError("CURSOR_EXPIRED", "Tag cursor is no longer available", 410)
        prior = decode(rows[0])
        if prior["kind"] != "user" or prior["scope_repo_id"] != repo_id:
            raise ContractError("CURSOR_EXPIRED", "Tag cursor is not in this dictionary", 410)
    query = "SELECT " + FIELDS + " FROM cf_tag FORCE INDEX (tag_scope) WHERE scope_repo_id=%s AND kind='user'"
    parameters = [repo_id]
    if after is not None:
        query += " AND tag_id>%s"
        parameters.append(after)
    query += " ORDER BY tag_id LIMIT %s FOR UPDATE"
    parameters.append(limit + 1)
    cursor.execute(query, tuple(parameters))
    values = [decode(row) for row in cursor.fetchall()]
    if (len(values) > limit + 1 or any(value["kind"] != "user" or value["scope_repo_id"] != repo_id for value in values)
            or len({value["tag_id"] for value in values}) != len(values)):
        raise ContractError("TAGS_UNAVAILABLE", "Tag dictionary requires reconciliation", 503)
    return {"items": values[:limit], "next_after": values[limit - 1]["tag_id"] if len(values) > limit else None}
