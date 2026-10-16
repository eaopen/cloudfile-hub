"""Install only reviewed V2 DDL; verify structure without a new ledger table."""
from contextlib import contextmanager
import hashlib
import re


TABLES = frozenset({'cf_library_storage', 'cf_dir_acl', 'cf_sso_group_map'})
EDIT_TABLES = frozenset({'cf_edit_guard'})


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
