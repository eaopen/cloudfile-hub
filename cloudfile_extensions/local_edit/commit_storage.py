"""Pin actual durable intent shape; no DDL or transaction ownership."""
from ..common.errors import ContractError


def require_storage(sql):
    try:
        sql.execute("SELECT version FROM cf_schema_migration WHERE version='032_edit_commits' AND state='applied' AND step=1 FOR UPDATE")
        if sql.fetchall() != (("032_edit_commits",),):
            raise ValueError()
        sql.execute("SELECT commit_id FROM cf_edit_commit LIMIT 0 FOR UPDATE")
        sql.fetchall()
        sql.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_edit_commit'")
        if sql.fetchall() != (("InnoDB",),):
            raise ValueError()
        sql.execute("SELECT column_name,data_type,character_maximum_length,collation_name,is_nullable,datetime_precision,column_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='cf_edit_commit'")
        columns = {row[0]: row[1:] for row in sql.fetchall()}
        strings = dict(commit_id=("char", 36, "ascii_bin", "NO"), session_id=("char", 36, "ascii_bin", "NO"),
            provider=("varchar", 32, "utf8mb4_bin", "NO"), owner_user_id=("varchar", 225, "utf8mb4_bin", "NO"),
            device_id=("char", 36, "ascii_bin", "NO"), store_id=("char", 36, "ascii_bin", "NO"),
            upload_sha256=("char", 64, "ascii_bin", "NO"), state=("varchar", 12, "ascii_bin", "NO"),
            new_file_id=("char", 40, "ascii_bin", "YES"), published_head=("char", 40, "ascii_bin", "YES"))
        numbers = ("device_revision", "session_revision", "upload_bytes", "revision")
        dates = ("created_at", "updated_at")
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
        sql.execute("SELECT index_name,column_name,seq_in_index,sub_part,non_unique FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='cf_edit_commit' ORDER BY index_name,seq_in_index")
        indexes = {}
        for name, column, position, prefix, non_unique in sql.fetchall():
            indexes.setdefault(name, []).append((column, position, prefix, non_unique))
        expected = dict(PRIMARY=[("commit_id", 1, None, 0)], session_commit=[("session_id", 1, None, 0)],
            owner_commits=[("provider", 1, None, 1), ("owner_user_id", 2, None, 1), ("commit_id", 3, None, 1)],
            pending=[("state", 1, None, 1), ("updated_at", 2, None, 1), ("commit_id", 3, None, 1)])
        if any(indexes.get(name) != shape for name, shape in expected.items()):
            raise ValueError()
    except Exception:
        raise ContractError("LOCAL_COMMIT_PENDING", "Local commit storage requires reconciliation", 503) from None
