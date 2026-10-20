"""Install only reviewed V2 DDL; verify structure without a new ledger table."""
from contextlib import contextmanager
import hashlib
import re


TABLES = frozenset({'cf_library_storage', 'cf_dir_acl', 'cf_sso_group_map'})
EDIT_TABLES = frozenset({'cf_edit_guard'})


# Structural signatures for a *read-only* preflight. The canonical DDL
# remains in cloudfile-server/scripts/sql/mysql/cloudfile-v2[-edit].sql; the
# full verification below compares CREATE TABLE rather than approximating it.
# This bounded inventory only classifies absent/current/legacy/mixed installs.
V2_FIELDS = {
    'cf_library_storage': {'repo_key': ('varchar', 80), 'repo_id': ('char', 36),
                           'state': ('varchar', 8)},
    'cf_sso_group_map': {'provider': ('varchar', 32), 'subject_type': ('varchar', 4),
                         'namespace': ('varchar', 128), 'external_id': ('varchar', 225),
                         'group_id': ('bigint', None)},
    'cf_dir_acl': {'repo_id': ('char', 36), 'path_hash': ('binary', 32),
                   'path': ('varchar', 4096), 'subject_type': ('varchar', 4),
                   'provider': ('varchar', 32), 'namespace': ('varchar', 128),
                   'external_id': ('varchar', 225), 'permission': ('varchar', 9),
                   'inherit': ('tinyint', None), 'share_mode': ('tinyint', None),
                   'revision': ('char', 36)},
    'cf_edit_guard': {'repo_id': ('char', 36), 'path_hash': ('binary', 32),
                      'path': ('varchar', 4096), 'guard_id': ('char', 36),
                      'generation': ('bigint', None), 'owner_uid': ('varchar', 225),
                      'owner_native_user': ('varchar', 255),
                      'terminal_type': ('varchar', 16),
                      'terminal_name': ('varchar', 128),
                      'checkout_ip': ('varchar', 45),
                      'proof_digest': ('char', 64),
                      'base_file_id': ('char', 40),
                      'lease_expires_at': ('datetime', None),
                      'created_at': ('datetime', None),
                      'updated_at': ('datetime', None)},
}
V2_INDEXES = {
    'cf_library_storage': {'PRIMARY': ('repo_key',),
                           'library_storage_repo': ('repo_id',)},
    'cf_sso_group_map': {'PRIMARY': ('provider', 'subject_type', 'namespace', 'external_id'),
                         'sso_native_group': ('group_id',)},
    'cf_dir_acl': {'PRIMARY': ('repo_id', 'path_hash', 'subject_type', 'provider',
                               'namespace', 'external_id'),
                   'acl_shared_subject': ('provider', 'subject_type', 'namespace',
                                          'external_id', 'share_mode', 'repo_id')},
    'cf_edit_guard': {'PRIMARY': ('repo_id', 'path_hash'),
                      'cf_edit_guard_id': ('guard_id',),
                      'cf_edit_guard_active': ('repo_id', 'guard_id'),
                      'cf_edit_guard_owner': ('owner_uid', 'guard_id')},
}


def classify_v2_table(name, columns, indexes):
    expected = V2_FIELDS[name]
    if not columns:
        return 'missing'
    if (set(columns) == set(expected)
            and all(columns[key] == signature for key, signature in expected.items())
            and all(indexes.get(key) == names for key, names in V2_INDEXES[name].items())):
        return 'current'
    if ({'resource_uid', 'lifecycle_ref', 'lease_until', 'subject_hash'} & set(columns)
            or (name == 'cf_sso_group_map' and 'id' in columns)):
        return 'legacy'
    return 'incompatible'


class SchemaError(RuntimeError):
    pass


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', value):
        raise ValueError('invalid database identifier')
    return '`' + value + '`'


@contextmanager
def database_lock(connection, key):
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE(),CONNECTION_ID()')
        database, owner = cursor.fetchone()
        name = 'cfv2:' + hashlib.sha256((database + ':' + key).encode()).hexdigest()[:56]
        cursor.execute('SELECT GET_LOCK(%s,5)', (name,))
        if cursor.fetchone() != (1,):
            raise SchemaError('database coordinator unavailable')
    try:
        yield
        with connection.cursor() as cursor:
            cursor.execute('SELECT IS_USED_LOCK(%s),CONNECTION_ID()', (name,))
            if cursor.fetchone() != (owner, owner):
                raise SchemaError('database coordinator changed')
    finally:
        with connection.cursor() as cursor:
            cursor.execute('SELECT RELEASE_LOCK(%s)', (name,))


def statements(ddl, *, allowed=TABLES):
    # The reviewed input contains only CREATE TABLE statements, never an upgrade.
    text = re.sub(r'--[^\n]*', '', ddl)
    result = {}
    for statement in text.split(';'):
        if not statement.strip():
            continue
        match = re.fullmatch(r'\s*CREATE TABLE (cf_[a-z_]+)\s*\([\s\S]+\)\s*ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin\s*', statement)
        if not match or match[1] not in allowed or match[1] in result:
            raise SchemaError('unreviewed V2 schema statement')
        result[match[1]] = statement.strip()
    if set(result) != allowed:
        raise SchemaError('incomplete V2 schema')
    return result


class FreshSchema:
    def __init__(self, connection, ddl, *, edit_ddl=None):
        if not connection.get_autocommit():
            raise ValueError('dedicated autocommit connection required')
        # One-table CF-EDIT is opt-in; the standard MVP
        # stays three tables and rejects unexpected additions by default.
        self.connection = connection
        self.tables = TABLES | EDIT_TABLES if edit_ddl is not None else TABLES
        self.ddl = statements(ddl)
        if edit_ddl is not None:
            self.ddl.update(statements(edit_ddl, allowed=EDIT_TABLES))

    def _tables(self, cursor):
        cursor.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()')
        return {row[0] for row in cursor.fetchall() if row[0].startswith('cf_')}

    def inspect(self):
        """Read-only metadata inventory: no DDL, no row data, no migration."""
        with self.connection.cursor() as cursor:
            existing = self._tables(cursor)
            rows = {}
            for name in sorted(V2_FIELDS):
                if name not in existing:
                    rows[name] = 'missing'
                    continue
                cursor.execute('SELECT COLUMN_NAME,DATA_TYPE,CHARACTER_MAXIMUM_LENGTH '
                               'FROM information_schema.COLUMNS WHERE table_schema=DATABASE() '
                               'AND table_name=%s', (name,))
                columns = {field: (kind.lower(), length)
                           for field, kind, length in cursor.fetchall()}
                cursor.execute('SELECT INDEX_NAME,COLUMN_NAME '
                               'FROM information_schema.STATISTICS '
                               'WHERE table_schema=DATABASE() AND table_name=%s '
                               'ORDER BY INDEX_NAME,SEQ_IN_INDEX', (name,))
                indexes = {}
                for index, field in cursor.fetchall():
                    indexes.setdefault(index, []).append(field)
                rows[name] = classify_v2_table(
                    name, columns, {index: tuple(fields) for index, fields in indexes.items()})
        extras = sorted(existing - set(V2_FIELDS))
        current = (all(rows[name] == 'current' for name in TABLES)
                   and rows['cf_edit_guard'] in ('missing', 'current')
                   and not extras)
        return {'status': 'current' if current else 'migration_review_required',
                'tables': rows, 'unexpected_cf_tables': extras}

    @staticmethod
    def _definition(cursor, name):
        cursor.execute('SHOW CREATE TABLE ' + identifier(name))
        # Only the table name differs for the disposable expected definition.
        definition = cursor.fetchone()[1]
        return definition[definition.index('('):]

    def _verify_one(self, cursor, name):
        expected = 'cfv2_expected'
        cursor.execute('DROP TEMPORARY TABLE IF EXISTS ' + expected)
        try:
            cursor.execute(self.ddl[name].replace('CREATE TABLE ' + name,
                                               'CREATE TEMPORARY TABLE ' + expected, 1))
            if self._definition(cursor, name) != self._definition(cursor, expected):
                raise SchemaError('V2 table definition has drifted: ' + name)
        finally:
            cursor.execute('DROP TEMPORARY TABLE IF EXISTS ' + expected)

    def verify(self):
        with self.connection.cursor() as cursor:
            if self._tables(cursor) != self.tables:
                raise SchemaError('V2 requires exactly the reviewed extension tables')
            for name in sorted(self.tables):
                self._verify_one(cursor, name)

    def install(self):
        with database_lock(self.connection, 'schema'):
            with self.connection.cursor() as cursor:
                present = self._tables(cursor)
                if present - self.tables:
                    raise SchemaError('legacy configuration present; no conversion is provided')
                # Check every existing table before creating any missing table.
                for name in sorted(present):
                    self._verify_one(cursor, name)
                for name in sorted(self.tables - present):
                    cursor.execute(self.ddl[name])
            self.verify()
