"""Pin actual session uniqueness/types under the current transaction's MDL."""
from ..common.errors import ContractError


def require_storage(sql):
    try:
        sql.execute("SELECT session_id FROM cf_edit_session LIMIT 0 FOR UPDATE")
        sql.fetchall()
        sql.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_edit_session'")
        if sql.fetchall() != (("InnoDB",),):
            raise ValueError()
        sql.execute("SELECT column_name,data_type,character_maximum_length,collation_name,is_nullable,datetime_precision,column_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='cf_edit_session'")
        columns = {row[0]: row[1:] for row in sql.fetchall()}
        strings = dict(session_id=("char", 36, "ascii_bin", "NO"), provider=("varchar", 32, "utf8mb4_bin", "NO"),
            owner_user_id=("varchar", 225, "utf8mb4_bin", "NO"), device_id=("char", 36, "ascii_bin", "NO"),
            state=("varchar", 12, "ascii_bin", "NO"), ticket_digest=("char", 64, "ascii_bin", "NO"))
        numbers, dates = ("device_revision", "ticket_expires_at", "expires_at", "revision"), ("created_at", "updated_at")
        if set(columns) != set(strings) | set(numbers) | set(dates) | {"snapshot"}:
            raise ValueError()
        if any(columns[name][:4] != shape for name, shape in strings.items()):
            raise ValueError()
        if columns["snapshot"][0] != "longtext" or columns["snapshot"][2:4] != ("utf8mb4_bin", "NO"):
            raise ValueError()
        if any(columns[name][:4] != ("bigint", None, None, "NO") or "unsigned" not in columns[name][5] for name in numbers):
            raise ValueError()
        if any(columns[name][:5] != ("datetime", None, None, "NO", 6) for name in dates):
            raise ValueError()
        sql.execute("SELECT index_name,column_name,seq_in_index,sub_part,non_unique FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_edit_session' ORDER BY index_name,seq_in_index")
        indexes = {}
        for name, column, position, prefix, non_unique in sql.fetchall():
            indexes.setdefault(name, []).append((column, position, prefix, non_unique))
        expected = dict(PRIMARY=[("session_id", 1, None, 0)],
            owner_sessions=[("provider", 1, None, 1), ("owner_user_id", 2, None, 1), ("session_id", 3, None, 1)],
            device_sessions=[("device_id", 1, None, 1), ("state", 2, None, 1), ("session_id", 3, None, 1)],
            expiry=[("expires_at", 1, None, 1), ("session_id", 2, None, 1)])
        if any(indexes.get(name) != shape for name, shape in expected.items()):
            raise ValueError()
    except Exception:
        raise ContractError("LOCAL_SESSION_PENDING", "Session storage requires reconciliation", 503) from None
