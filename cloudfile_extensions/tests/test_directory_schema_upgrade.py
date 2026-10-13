"""Exercise the release upgrade against real MariaDB, including legacy drift."""
from cloudfile_extensions.schema.directory import DirectorySchemaRunner
from cloudfile_extensions.schema.runner import MigrationError, SchemaRunner, load_migrations
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class DirectorySchemaUpgradeTest(DatabaseTestCase):
    def legacy(self):
        with self.connection.cursor() as cursor:
            for table in ('cf_dir_acl', 'cf_dir_admin'):
                permission = ',permission VARCHAR(16) NOT NULL' if table == 'cf_dir_acl' else ''
                cursor.execute('CREATE TABLE ' + table + '(id BIGINT PRIMARY KEY AUTO_INCREMENT,'
                    'repo_id CHAR(36) NOT NULL,path VARCHAR(1000) NOT NULL,path_hash CHAR(40) NOT NULL,'
                    'subject_type VARCHAR(16) NOT NULL,subject VARCHAR(255) NOT NULL,'
                    'inherit TINYINT NOT NULL,ctime BIGINT,mtime BIGINT' + permission + ') ENGINE=InnoDB')

    def test_fresh_and_repeat_use_same_ledger(self):
        runner = DirectorySchemaRunner(self.connection)
        with self.assertRaises(MigrationError):
            runner.apply()
        runner.apply(offline=True)
        runner.require_current()
        self.assertEqual(len(runner.plan()), 5)
        self.assertTrue(all(row['state'] == 'current' for row in runner.inspect()['tables']))
        runner.apply(offline=True)
        # A bounded directory upgrade must still compose with the full catalog.
        SchemaRunner(self.connection).apply()
        SchemaRunner(self.connection).require_current()

    def test_empty_legacy_is_archived_and_three_tables_upgraded(self):
        self.legacy()
        runner = DirectorySchemaRunner(self.connection)
        self.assertEqual([x['state'] for x in runner.inspect()['tables']], ['legacy', 'legacy', 'missing'])
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection).apply()
        self.assertEqual(runner.status(), [])
        runner.apply(offline=True)
        runner.apply(offline=True)
        runner.require_current()
        with self.connection.cursor() as cursor:
            for table in ('cf_dir_acl', 'cf_dir_admin'):
                cursor.execute('SELECT COUNT(*) FROM ' + table + '_legacy_v08')
                self.assertEqual(cursor.fetchone()[0], 0)

    def test_nonempty_legacy_rejected_before_any_rename(self):
        self.legacy()
        with self.connection.cursor() as cursor:
            cursor.execute("INSERT INTO cf_dir_admin(repo_id,path,path_hash,subject_type,subject,inherit) "
                           "VALUES('repo','/x','hash','user','someone',1)")
        runner = DirectorySchemaRunner(self.connection)
        with self.assertRaises(MigrationError):
            runner.apply(offline=True)
        self.assertEqual(runner.inspect()['tables'][0]['state'], 'legacy')
        self.assertEqual(runner.status(), [])

    def test_field_drift_is_not_hidden_by_column_names(self):
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('ALTER TABLE cf_dir_share MODIFY path_hash CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL')
        with self.assertRaises(MigrationError):
            runner.require_current()
        with self.assertRaises(MigrationError):
            runner.apply(offline=True)
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection).apply()

    def test_missing_index_is_detected(self):
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('ALTER TABLE cf_dir_admin DROP INDEX acl_library_page')
        with self.assertRaises(MigrationError):
            runner.require_current()

    def test_interrupted_archive_resumes_without_deleting_backup(self):
        self.legacy()
        with self.connection.cursor() as cursor:
            cursor.execute('RENAME TABLE cf_dir_acl TO cf_dir_acl_legacy_v08,cf_dir_admin TO cf_dir_admin_legacy_v08')
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        runner.require_current()

    def test_partial_dev_ledger_is_preserved(self):
        self.legacy()
        selected = [m for m in load_migrations() if m.version in
                    ('001_resources', '029_editing_core', '032_managed_libraries')]
        SchemaRunner(self.connection, selected).apply()
        before = SchemaRunner(self.connection).status()
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        after = {row['version']: row for row in runner.status()}
        for row in before:
            self.assertEqual(after[row['version']], row)
        runner.require_current()

    def test_backup_collision_leaves_both_tables_untouched(self):
        self.legacy()
        with self.connection.cursor() as cursor:
            cursor.execute('CREATE TABLE cf_dir_admin_legacy_v08(id INT)')
        runner = DirectorySchemaRunner(self.connection)
        with self.assertRaises(MigrationError):
            runner.apply(offline=True)
        self.assertEqual([x['state'] for x in runner.inspect()['tables']], ['legacy', 'legacy', 'missing'])

    def test_page_index_uniqueness_drift_is_rejected(self):
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('ALTER TABLE cf_dir_admin DROP INDEX acl_library_page, ADD UNIQUE KEY acl_library_page(repo_id,id)')
        with self.assertRaises(MigrationError):
            runner.require_current()
