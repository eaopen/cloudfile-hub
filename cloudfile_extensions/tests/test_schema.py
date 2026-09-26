"""Real, isolated MariaDB tests; never run against an unmarked user database."""

import os
import unittest
from uuid import uuid4

from cloudfile_extensions.schema.runner import Migration, MigrationError, SchemaRunner


@unittest.skipUnless(os.environ.get("CF_TEST_DB_PORT"), "requires an isolated CloudFile test database")
class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        import pymysql
        self.options = dict(host="127.0.0.1", port=int(os.environ["CF_TEST_DB_PORT"]),
                            user="root", password="", autocommit=True, charset="utf8mb4")
        self.admin = pymysql.connect(**self.options)
        self.database = "cf_test_" + uuid4().hex
        with self.admin.cursor() as cursor:
            cursor.execute("CREATE DATABASE " + self.database)
        self.connection = pymysql.connect(**self.options, database=self.database)

    def tearDown(self):
        self.connection.close()
        # The exact database was created by this setUp; no pre-existing schema is touched.
        with self.admin.cursor() as cursor:
            cursor.execute("DROP DATABASE " + self.database)
        self.admin.close()


class SchemaRunnerTest(DatabaseTestCase):

    def test_corrupt_ledger_and_duplicate_definitions_are_rejected(self):
        runner = SchemaRunner(self.connection)
        runner.apply()
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE cf_schema_migration SET state='applied',step=0")
        with self.assertRaises(MigrationError):
            runner.require_current()
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection, runner.migrations + runner.migrations)

    def test_fresh_install_repeat_and_current_version(self):
        runner = SchemaRunner(self.connection)
        self.assertEqual(runner.plan()[0]["state"], "pending")
        with self.assertRaises(MigrationError):
            runner.require_current()
        self.assertEqual(runner.apply()[0]["state"], "applied")
        self.assertEqual(runner.apply()[0]["step"], 1)
        runner.require_current()

    def test_checksum_drift_cannot_be_silently_applied(self):
        runner = SchemaRunner(self.connection)
        runner.apply()
        changed = Migration(runner.migrations[0].version, ({"sql": "SELECT 1", "verify": "SELECT 1", "expected": 1},))
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection, (changed,)).apply()

    def test_structure_drift_is_rejected(self):
        runner = SchemaRunner(self.connection)
        runner.apply()
        with self.connection.cursor() as cursor:
            cursor.execute("ALTER TABLE cf_resource MODIFY path TEXT COLLATE utf8mb4_bin NOT NULL")
        with self.assertRaises(MigrationError):
            runner.require_current()
        with self.assertRaises(MigrationError):
            runner.apply()

    def test_second_runner_cannot_acquire_live_lock(self):
        import pymysql
        second = pymysql.connect(**self.options, database=self.database)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT GET_LOCK('cloudfile.schema.v1', 0)")
            with self.assertRaises(MigrationError):
                SchemaRunner(second).apply()
        finally:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK('cloudfile.schema.v1')")
            second.close()

    def test_failed_ddl_resumes_from_verified_actual_structure(self):
        def step(table, sql):
            return {"sql": sql, "verify": "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='" + table + "'", "expected": 1}
        migration = Migration("001_recovery", (
            step("cf_first", "CREATE TABLE cf_first(id INT)"),
            step("cf_recovered", "INVALID SQL"),
        ))
        runner = SchemaRunner(self.connection, (migration,))
        with self.assertRaises(MigrationError):
            runner.apply()
        self.assertEqual(runner.status()[0]["state"], "failed")
        self.assertEqual(runner.status()[0]["step"], 1)
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE cf_recovered(id INT)")
        self.assertEqual(runner.apply()[0]["state"], "applied")

    def test_existing_table_upgrade_preserves_original_rows(self):
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE cf_legacy(id INT PRIMARY KEY, data VARCHAR(32))")
            cursor.execute("INSERT INTO cf_legacy VALUES(1,'keep')")
        migration = Migration("001_upgrade", ({
            "sql": "ALTER TABLE cf_legacy ADD revision BIGINT NOT NULL DEFAULT 1",
            "verify": "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='cf_legacy' AND column_name='revision'",
            "expected": 1,
        },))
        SchemaRunner(self.connection, (migration,)).apply()
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data,revision FROM cf_legacy WHERE id=1")
            self.assertEqual(cursor.fetchone(), ("keep", 1))
