"""Fresh-install SQL dumps must carry the CloudFile fork schema.

A new CE14 installation imports ``seahub/sql/mysql.sql`` (docker image) or
``seahub/sql/sqlite3.sql`` (local setup script) instead of running Django
migrations.  Fork migrations that add columns only exist as migrations, so a
fresh install silently created tables without them and the native share /
favorites / tags endpoints returned 500 (share_extrasharepermission.
auto_granted_access, base_userstarredfiles.obj_id, repo_tags_repotags.
is_system).

These checks are pure text assertions over the dumps so they stay cheap for
quick source CI; they intentionally do not claim an acceptance result for the
endpoints themselves.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]

FORK_COLUMNS = {
    'share_extrasharepermission':
        ('auto_granted_access', 'auto_granted_permission',
         'auto_grant_previous_permission'),
    'share_extragroupssharepermission':
        ('auto_granted_access', 'auto_granted_permission',
         'auto_grant_previous_permission'),
    'base_userstarredfiles': ('obj_id',),
    'repo_tags_repotags': ('is_system',),
}

FORK_MIGRATIONS = {
    ('base', '0005_userstarredfiles_obj_id'),
    ('repo_tags', '0002_repotags_is_system'),
    ('share', '0003_unique_library_administrators'),
    ('share', '0004_library_admin_auto_read'),
    ('share', '0005_library_admin_auto_rw'),
}


def _read(name):
    return (ROOT / 'sql' / name).read_text()


def _mysql_table(sql, table):
    match = re.search(r'CREATE TABLE `%s` \(([\s\S]*?)\) ENGINE=' % re.escape(table), sql)
    if match is None:
        raise AssertionError('CREATE TABLE `%s` not found in sql/mysql.sql' % table)
    return match.group(1)


def _sqlite_table(sql, table):
    match = re.search(r'CREATE TABLE "%s" \(([\s\S]*?)\);' % re.escape(table), sql)
    if match is None:
        raise AssertionError('CREATE TABLE "%s" not found in sql/sqlite3.sql' % table)
    return match.group(1)


def _mysql_migrations(sql):
    return set(re.findall(r"\(\d+,'([a-z0-9_]+)','([a-z0-9_]+)'", sql))


def _sqlite_migrations(sql):
    return set(re.findall(
        r"INSERT INTO \"django_migrations\" VALUES\(\d+,'([a-z0-9_]+)','([a-z0-9_]+)'",
        sql))


class FreshInstallSchemaTest(unittest.TestCase):
    def test_mysql_fresh_install_has_fork_columns(self):
        sql = _read('mysql.sql')
        for table, columns in FORK_COLUMNS.items():
            body = _mysql_table(sql, table)
            for column in columns:
                self.assertIn('`%s`' % column, body,
                              'sql/mysql.sql: %s.%s missing' % (table, column))
        self.assertIn('UNIQUE KEY `unique_library_user_admin`', sql)
        self.assertIn('UNIQUE KEY `unique_library_group_admin`', sql)
        self.assertIn('KEY `base_userstarredfiles_obj_id`', sql)
        self.assertIn('KEY `repo_tags_repotags_is_system`', sql)

    def test_sqlite_fresh_install_has_fork_columns(self):
        sql = _read('sqlite3.sql')
        for table, columns in FORK_COLUMNS.items():
            body = _sqlite_table(sql, table)
            for column in columns:
                self.assertIn('"%s"' % column, body,
                              'sql/sqlite3.sql: %s.%s missing' % (table, column))
        self.assertIn('"unique_library_user_admin"', sql)
        self.assertIn('"unique_library_group_admin"', sql)

    def test_fork_migrations_are_recorded_as_applied(self):
        # Fresh installs skip `manage.py migrate`; the dump's django_migrations
        # rows must already cover the fork migrations or a later migrate would
        # replay them against columns that already exist.
        for name, parser in (('mysql.sql', _mysql_migrations),
                             ('sqlite3.sql', _sqlite_migrations)):
            recorded = parser(_read(name))
            self.assertTrue(FORK_MIGRATIONS <= recorded,
                            '%s is missing fork migration rows: %s'
                            % (name, sorted(FORK_MIGRATIONS - recorded)))


if __name__ == '__main__':
    unittest.main()
