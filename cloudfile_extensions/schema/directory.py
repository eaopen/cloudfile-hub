"""One migration owner for ACL, delegated administration and directory shares.

Definitions come from the immutable migration DDL, not another bootstrap SQL
copy. Offline upgrades retain empty legacy tables as backups; populated legacy
subjects cannot be translated into qualified identities by guessing.
"""
import re
from functools import lru_cache

from .runner import MigrationError, SchemaRunner, load_migrations


TABLES = ('cf_dir_acl', 'cf_dir_admin', 'cf_dir_share')
VERSIONS = frozenset(('008_directory_acl', '009_directory_admins',
                     '036_library_acl_page', '040_directory_shares',
                     '041_directory_admin_page'))
LEGACY_COLUMNS = {'id', 'repo_id', 'path', 'path_hash', 'subject_type',
                  'subject', 'inherit', 'ctime', 'mtime'}


@lru_cache(maxsize=1)
def contracts():
    """Read field contracts from the same DDL used to create the tables."""
    result = {}
    for migration in load_migrations():
        for step in migration.steps:
            match = re.match(r'CREATE TABLE (cf_dir_\w+) \((.*)\) ENGINE=InnoDB', step['sql'])
            if not match or match[1] not in TABLES:
                continue
            columns = {}
            for definition in re.split(r',\s*(?![^()]*\))', match[2]):
                field = re.match(r'(\w+) (CHAR\(\d+\)|VARCHAR\(\d+\)|TEXT|TINYINT|DATETIME\(\d+\))(.*)', definition)
                if not field:
                    continue
                collation = re.search(r'COLLATE (\w+)', field[3])
                columns[field[1]] = (field[2].lower(), collation[1] if collation else None, 'NO')
            result[match[1]] = columns
    if set(result) != set(TABLES):
        raise MigrationError('directory migration definitions are incomplete')
    return result


def verify_indexes(runner):
    """Validate index order and uniqueness, including later page indexes."""
    expected = {table: {'PRIMARY': (0, ('id',))} for table in TABLES}
    for migration in runner.migrations:
        if migration.version not in VERSIONS:
            continue
        for step in migration.steps:
            sql = step['sql']
            table = re.match(r'(?:CREATE|ALTER) TABLE (\w+) ', sql)[1]
            for unique, name, columns in re.findall(r'(UNIQUE )?KEY (\w+)\(([^)]+)\)', sql):
                expected[table][name] = (0 if unique else 1, tuple(columns.split(',')))
    for table, indexes in expected.items():
        rows = runner._query('SELECT INDEX_NAME,NON_UNIQUE,COLUMN_NAME,SUB_PART '
                             'FROM information_schema.statistics WHERE table_schema=DATABASE() '
                             'AND table_name=%s ORDER BY INDEX_NAME,SEQ_IN_INDEX', (table,))
        for name, (non_unique, columns) in indexes.items():
            actual = [(column, unique, prefix) for index, unique, column, prefix in rows if index == name]
            if actual != [(column, non_unique, None) for column in columns]:
                return False
    return True


def inspect_tables(runner):
    result = []
    for table, expected in contracts().items():
        rows = runner._query('SELECT COLUMN_NAME,COLUMN_TYPE,COLLATION_NAME,IS_NULLABLE '
                             'FROM information_schema.columns WHERE table_schema=DATABASE() '
                             'AND table_name=%s', (table,))
        # Integer display widths differ between MySQL and MariaDB.
        actual = {name: (re.sub(r'^tinyint\(\d+\)$', 'tinyint', kind.lower()), collation, nullable)
                  for name, kind, collation, nullable in rows}
        engine = runner._query('SELECT ENGINE FROM information_schema.tables '
                               'WHERE table_schema=DATABASE() AND table_name=%s', (table,))
        state = 'missing' if not actual else 'current' if actual == expected and engine == (('InnoDB',),) else 'incompatible'
        legacy = LEGACY_COLUMNS | ({'permission'} if table == 'cf_dir_acl' else set())
        if (table != 'cf_dir_share' and set(actual) == legacy and
                actual.get('path_hash', ('',))[0] == 'char(40)' and
                actual.get('id', ('',))[0].startswith('bigint') and engine == (('InnoDB',),)):
            state = 'legacy'
        result.append({'table': table, 'state': state})
    return result


class DirectorySchemaRunner(SchemaRunner):
    """A bounded release operation using the shared ledger and migration lock."""

    def plan(self):
        # Keep the complete catalog so unrelated applied versions are recognized.
        return [row for row in super().plan() if row['version'] in VERSIONS]

    def inspect(self):
        return {'tables': inspect_tables(self), 'migrations': self.plan()}

    def require_current(self):
        if any(row['state'] != 'current' for row in inspect_tables(self)):
            raise MigrationError('directory table layout is not current')
        if any(row['state'] != 'applied' for row in self.plan()):
            raise MigrationError('directory schema upgrade is required')
        if not all(self._verify(step) for migration in self.migrations
                   if migration.version in VERSIONS for step in migration.steps):
            raise MigrationError('directory indexes or structure have drifted')
        if not verify_indexes(self):
            raise MigrationError('directory index contract has drifted')

    def apply(self, *, offline=False):
        if offline is not True:
            raise MigrationError('stop directory readers and writers before an offline upgrade')
        with self._locked():
            plan = {row['version']: row for row in self.plan()}
            tables = inspect_tables(self)
            if any(row['state'] == 'incompatible' for row in tables):
                raise MigrationError('unsupported directory table layout; no tables changed')
            legacy = [row['table'] for row in tables if row['state'] == 'legacy']
            # Preflight every table before the first DDL: an unsupported table
            # must not leave half of the directory authority upgraded.
            for table in legacy:
                if self._query('SELECT COUNT(*) FROM ' + table)[0][0]:
                    raise MigrationError('legacy directory rules require explicit identity conversion')
                if self._query('SELECT COUNT(*) FROM information_schema.tables '
                               'WHERE table_schema=DATABASE() AND table_name=%s', (table + '_legacy_v08',))[0][0]:
                    raise MigrationError('legacy directory backup already exists')
                version = '008_directory_acl' if table == 'cf_dir_acl' else '009_directory_admins'
                if plan[version]['state'] != 'pending':
                    raise MigrationError('legacy directory table conflicts with the migration ledger')
            self._bootstrap()
            if legacy:
                # One atomic rename keeps both old tables available for recovery.
                self._query('RENAME TABLE ' + ','.join(table + ' TO ' + table + '_legacy_v08' for table in legacy))
            for migration in self.migrations:
                if migration.version in VERSIONS:
                    self._apply_one(migration, plan[migration.version])
            self.require_current()
        return self.inspect()
