"""Actual intent schema checks, not worker or native publication evidence."""
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.local_edit.commit_storage import require_storage
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class LocalCommitStorageTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()

    def test_intent_schema_preserves_existing_audit_paths_and_repeat_apply(self):
        # New intent storage must not invalidate the established audit schema.
        SchemaRunner(self.connection).apply()
        SchemaRunner(self.connection).require_current()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                require_storage(sql)
                sql.execute("SELECT data_type FROM information_schema.columns "
                    "WHERE table_schema=DATABASE() AND table_name='cf_audit_event' "
                    "AND column_name IN ('source_path','target_path') ORDER BY column_name")
                self.assertEqual(sql.fetchall(), (("longtext",), ("longtext",)))
        finally:
            self.connection.rollback()

    def test_actual_shape_drift_is_rejected_without_repair_ddl(self):
        with self.connection.cursor() as sql:
            sql.execute("ALTER TABLE cf_edit_commit MODIFY owner_user_id "
                "VARCHAR(255) COLLATE utf8mb4_bin NOT NULL")
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                with self.assertRaises(ContractError) as raised:
                    require_storage(sql)
                self.assertEqual(raised.exception.code, "LOCAL_COMMIT_PENDING")
                sql.execute("SELECT character_maximum_length FROM information_schema.columns "
                    "WHERE table_schema=DATABASE() AND table_name='cf_edit_commit' "
                    "AND column_name='owner_user_id'")
                self.assertEqual(sql.fetchone()[0], 255)
        finally:
            self.connection.rollback()
