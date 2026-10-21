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
        self.assertEqual(len(runner.plan()), 6)
        self.assertTrue(all(row['state'] == 'current' for row in runner.inspect()['tables']))
        runner.apply(offline=True)
        # A bounded directory upgrade must still compose with the full catalog.
        SchemaRunner(self.connection).apply()
        SchemaRunner(self.connection).require_current()

    def test_empty_legacy_is_archived_and_two_tables_upgraded(self):
        self.legacy()
        runner = DirectorySchemaRunner(self.connection)
        self.assertEqual([x['state'] for x in runner.inspect()['tables']], ['legacy', 'legacy'])
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
            cursor.execute('ALTER TABLE cf_dir_acl MODIFY path_hash CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL')
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
        self.assertEqual([x['state'] for x in runner.inspect()['tables']], ['legacy', 'legacy'])

    def test_page_index_uniqueness_drift_is_rejected(self):
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('ALTER TABLE cf_dir_admin DROP INDEX acl_library_page, ADD UNIQUE KEY acl_library_page(repo_id,id)')
        with self.assertRaises(MigrationError):
            runner.require_current()


class UnifiedDirectoryUpgradeTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        # Preserve the published 040 migration definition and its checksum.
        SchemaRunner(self.connection, [m for m in load_migrations()
            if m.version != '042_unified_directory_acl']).apply()

    def seed(self, *, acl_permission=None):
        from uuid import uuid4
        from cloudfile_extensions.authorization.rules import ACLRules, digest
        repo, id_, revision = str(uuid4()), str(uuid4()), str(uuid4())
        subject = dict(type='user', provider='directory', namespace='user', external_id='employee')
        with self.connection.cursor() as cursor:
            cursor.execute('INSERT INTO cf_dir_share(id,repo_id,path,path_hash,lifecycle_ref,subject_type,provider,namespace,'
                'external_id,subject_hash,revision,created_by,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(6))',
                (id_, repo, '/team', digest('/team'), 'birth', 'user', 'directory', 'user', 'employee',
                 ACLRules._subject_hash(subject), revision, 'admin'))
            acl_id = str(uuid4())
            if acl_permission:
                # Real ACL publication enrolls a managed library. The 032
                # schema invariant must remain valid after dropping 040.
                cursor.execute('INSERT INTO cf_managed_library(repo_id,created_at) VALUES(%s,UTC_TIMESTAMP(6))', (repo,))
                cursor.execute('INSERT INTO cf_dir_acl(' + ACLRules.FIELDS.rsplit(',', 2)[0] + ') VALUES(' +
                    ','.join(['%s'] * 13) + ')', (acl_id, repo, '/team', digest('/team'), 'dir', 'user', 'directory',
                    'user', 'employee', ACLRules._subject_hash(subject), acl_permission, 0, str(uuid4())))
        return id_, acl_id

    def test_direct_drop_preserves_existing_acl_without_importing_old_shares(self):
        share, _ = self.seed()
        _, acl = self.seed(acl_permission='rw')
        _, deny = self.seed(acl_permission='none')
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection).apply()
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT id,permission,inherit,share_mode,lifecycle_ref FROM cf_dir_acl')
            self.assertEqual({row[0]: row[1:] for row in cursor.fetchall()}, {
                acl: ('rw', 0, 0, ''), deny: ('none', 0, 0, '')})
            cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_dir_share'")
            self.assertEqual(cursor.fetchone()[0], 0)
        runner.apply(offline=True)
        SchemaRunner(self.connection).apply()
        runner.require_current()
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_dir_acl WHERE id=%s', (share,))
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_invalid_old_share_content_does_not_block_deletion(self):
        self.seed()
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE cf_dir_share SET subject_hash=REPEAT('0',64)")
        DirectorySchemaRunner(self.connection).apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_dir_acl')
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_dir_share'")
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_crash_after_drop_resumes_without_recreating_table(self):
        self.seed()
        runner = DirectorySchemaRunner(self.connection)
        original = runner._query
        def crash(sql, parameters=()):
            if sql.startswith("UPDATE cf_schema_migration SET step=") and parameters == (3, '042_unified_directory_acl'):
                raise RuntimeError('simulated crash after committed DROP')
            return original(sql, parameters)
        runner._query = crash
        with self.assertRaises(MigrationError):
            runner.apply(offline=True)
        runner = DirectorySchemaRunner(self.connection)
        runner.apply(offline=True)
        runner.require_current()
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) FROM cf_dir_acl')
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='cf_dir_share'")
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_existing_acl_id_does_not_merge_or_rotate(self):
        share, _ = self.seed()
        _, other_acl = self.seed(acl_permission='rw')
        with self.connection.cursor() as cursor:
            cursor.execute('UPDATE cf_dir_acl SET id=%s WHERE id=%s', (share, other_acl))
            cursor.execute('SELECT id,revision,permission FROM cf_dir_acl')
            before = cursor.fetchall()
        DirectorySchemaRunner(self.connection).apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT id,revision,permission FROM cf_dir_acl')
            self.assertEqual(cursor.fetchall(), before)

    def test_crash_before_drop_retries_without_mutating_acl(self):
        self.seed(acl_permission='rw')
        runner = DirectorySchemaRunner(self.connection)
        original = runner._query
        def crash(sql, parameters=()):
            if sql == 'DROP TABLE cf_dir_share':
                raise RuntimeError('simulated failure before DROP')
            return original(sql, parameters)
        runner._query = crash
        with self.assertRaises(MigrationError):
            runner.apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT id,revision,permission,share_mode FROM cf_dir_acl')
            before = cursor.fetchall()
            cursor.execute('SELECT COUNT(*) FROM cf_dir_share')
            self.assertEqual(cursor.fetchone()[0], 1)
        DirectorySchemaRunner(self.connection).apply(offline=True)
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT id,revision,permission,share_mode FROM cf_dir_acl')
            self.assertEqual(cursor.fetchall(), before)
