"""Read-only qualification of the optional path-keyed Checkout store.

Ordinary file reads/writes do not need this capability or a Checkout session.
The resource-keyed store uses the same table name and must never be mistaken
for the optional Rust/path store or silently rewritten by discovery.
"""

PATH_COLUMNS = frozenset({
    'repo_id', 'path_hash', 'path', 'guard_id', 'generation', 'owner_uid',
    'owner_native_user', 'terminal_type', 'terminal_name', 'checkout_ip',
    'proof_digest', 'base_file_id', 'lease_expires_at', 'created_at', 'updated_at',
})
RESOURCE_COLUMNS = frozenset({
    'resource_uid', 'repo_id', 'lifecycle_ref', 'guard_id', 'generation', 'mode',
    'owner', 'owner_native_user', 'source', 'holder', 'credential_epoch',
    'proof_digest', 'base_file_id', 'pending_intent', 'lease_until', 'hard_expire_at',
})
PATH_INDEXES = {
    'PRIMARY': (0, ('repo_id', 'path_hash')),
    'cf_edit_guard_id': (0, ('guard_id',)),
    'cf_edit_guard_active': (1, ('repo_id', 'guard_id')),
    'cf_edit_guard_owner': (1, ('owner_uid', 'guard_id')),
}


def path_checkout_available(connection, schema):
    """Qualify the installed contract without issuing DDL or starting an edit."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA=%s AND TABLE_NAME='cf_edit_guard'", (schema,))
        columns = {row[0] for row in cursor.fetchall()}
        if not columns or columns == RESOURCE_COLUMNS:
            return False
        if columns != PATH_COLUMNS:
            raise RuntimeError('Checkout table structure does not match the reviewed path store')
        cursor.execute(
            "SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,SUB_PART "
            "FROM information_schema.STATISTICS "
            "WHERE TABLE_SCHEMA=%s AND TABLE_NAME='cf_edit_guard' "
            "ORDER BY INDEX_NAME,SEQ_IN_INDEX", (schema,))
        indexes = {}
        for name, non_unique, sequence, column, prefix in cursor.fetchall():
            unique, parts = indexes.setdefault(name, (non_unique, []))
            if prefix is not None or unique != non_unique or sequence != len(parts) + 1:
                raise RuntimeError('Checkout index structure is invalid')
            parts.append(column)
        actual = {name: (unique, tuple(parts)) for name, (unique, parts) in indexes.items()}
        if any(actual.get(name) != definition for name, definition in PATH_INDEXES.items()):
            raise RuntimeError('Checkout indexes do not match the reviewed path store')
        return True
