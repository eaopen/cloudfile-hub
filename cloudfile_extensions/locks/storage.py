"""Verify actual lease table constraints, not merely a migration receipt."""
from ..common.errors import ContractError


def require_storage(sql):
    try:
        for table, primary in (("cf_lock_lease", "resource_uid"), ("cf_lock_repo_revision", "repo_id")):
            sql.execute("SELECT " + primary + " FROM " + table + " LIMIT 0 FOR UPDATE")
            sql.fetchall()
            sql.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            if sql.fetchall() != (("InnoDB",),):
                raise ValueError()
            sql.execute("SELECT column_name,data_type,character_maximum_length,collation_name,is_nullable,datetime_precision,column_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            columns = {row[0]: row[1:] for row in sql.fetchall()}
            strings = {"repo_id": ("char", 36, "ascii_bin", "NO")}
            number = "revision"
            if table == "cf_lock_lease":
                number = "fencing"
                strings.update(resource_uid=("char", 36, "ascii_bin", "NO"),
                    owner_user_id=("varchar", 225, "utf8mb4_bin", "YES"),
                    holder_id=("varchar", 128, "utf8mb4_bin", "YES"),
                    token_digest=("char", 64, "ascii_bin", "YES"),
                    base_version=("char", 40, "ascii_bin", "YES"))
            if set(columns) != set(strings) | {number} | ({"expires_at"} if table == "cf_lock_lease" else set()):
                raise ValueError()
            if any(columns[name][:4] != shape for name, shape in strings.items()):
                raise ValueError()
            numeric = columns[number]
            if numeric[:4] != ("bigint", None, None, "NO") or "unsigned" not in numeric[5]:
                raise ValueError()
            if table == "cf_lock_lease" and columns["expires_at"][:5] != ("datetime", None, None, "YES", 6):
                raise ValueError()
            sql.execute("SELECT index_name,column_name,seq_in_index,sub_part,non_unique FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=%s ORDER BY index_name,seq_in_index", (table,))
            indexes = {}
            for name, column, position, prefix, non_unique in sql.fetchall():
                indexes.setdefault(name, []).append((column, position, prefix, non_unique))
            if indexes.get("PRIMARY") != [(primary, 1, None, 0)]:
                raise ValueError()
            if table == "cf_lock_lease" and indexes.get("repo_leases") != [("repo_id", 1, None, 1), ("resource_uid", 2, None, 1)]:
                raise ValueError()
    except Exception:
        raise ContractError("LOCK_STATE_PENDING", "Lease storage requires reconciliation", 503) from None
