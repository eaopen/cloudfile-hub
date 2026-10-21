"""Actual device constraints pinned by request transaction metadata locks."""
from ..common.errors import ContractError


def require_storage(sql):
    try:
        for table, primary in (("cf_local_device", "device_id"), ("cf_local_device_challenge", "nonce_digest")):
            sql.execute("SELECT " + primary + " FROM " + table + " LIMIT 0 FOR UPDATE")
            sql.fetchall()
            sql.execute("SELECT ENGINE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            if sql.fetchall() != (("InnoDB",),):
                raise ValueError()
            sql.execute("SELECT column_name,data_type,character_maximum_length,collation_name,is_nullable,datetime_precision,column_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            columns = {row[0]: row[1:] for row in sql.fetchall()}
            strings = dict(device_id=("char", 36, "ascii_bin", "NO"))
            if table == "cf_local_device":
                strings.update(provider=("varchar", 32, "utf8mb4_bin", "NO"),
                    owner_user_id=("varchar", 225, "utf8mb4_bin", "NO"),
                    key_x=("char", 43, "ascii_bin", "NO"), key_y=("char", 43, "ascii_bin", "NO"),
                    key_thumbprint=("char", 43, "ascii_bin", "NO"), state=("varchar", 8, "ascii_bin", "NO"))
                numbers, dates = ("revision",), {"updated_at": "NO"}
                expected_indexes = dict(PRIMARY=[("device_id", 1, None, 0)],
                    owner_key=[("provider", 1, None, 0), ("owner_user_id", 2, None, 0), ("key_thumbprint", 3, None, 0)],
                    owner_devices=[("provider", 1, None, 1), ("owner_user_id", 2, None, 1), ("device_id", 3, None, 1)])
            else:
                strings.update(nonce_digest=("char", 64, "ascii_bin", "NO"),
                    instance=("varchar", 255, "ascii_bin", "NO"), session_id=("char", 36, "ascii_bin", "NO"),
                    operation=("varchar", 8, "ascii_bin", "NO"), request_sha256=("char", 64, "ascii_bin", "NO"))
                numbers, dates = ("device_revision", "issued_at", "expires_at"), {"consumed_at": "YES"}
                expected_indexes = dict(PRIMARY=[("nonce_digest", 1, None, 0)],
                    device_expiry=[("device_id", 1, None, 1), ("expires_at", 2, None, 1)],
                    expiry=[("expires_at", 1, None, 1), ("nonce_digest", 2, None, 1)])
            if set(columns) != set(strings) | set(numbers) | set(dates):
                raise ValueError()
            if any(columns[name][:4] != shape for name, shape in strings.items()):
                raise ValueError()
            if any(columns[name][:4] != ("bigint", None, None, "NO") or "unsigned" not in columns[name][5] for name in numbers):
                raise ValueError()
            if any(columns[name][:5] != ("datetime", None, None, nullable, 6) for name, nullable in dates.items()):
                raise ValueError()
            sql.execute("SELECT index_name,column_name,seq_in_index,sub_part,non_unique FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=%s ORDER BY index_name,seq_in_index", (table,))
            indexes = {}
            for name, column, position, prefix, non_unique in sql.fetchall():
                indexes.setdefault(name, []).append((column, position, prefix, non_unique))
            if any(indexes.get(name) != shape for name, shape in expected_indexes.items()):
                raise ValueError()
    except Exception:
        raise ContractError("DEVICE_STATE_PENDING", "Device storage requires reconciliation", 503) from None
