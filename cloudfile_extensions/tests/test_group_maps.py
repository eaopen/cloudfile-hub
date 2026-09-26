from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.group_maps import GroupMaps
from cloudfile_extensions.schema.runner import MigrationError, SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class GroupMapTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.maps = GroupMaps(self.connection)

    def insert(self, provider="directory", kind="dept", namespace="directory", external="部门:一", group=1):
        with self.connection.cursor() as cursor:
            cursor.execute("INSERT INTO cf_sso_group_map(provider,subject_type,namespace,external_id,group_id,name) VALUES(%s,%s,%s,%s,%s,'display-only')",
                           (provider, kind, namespace, external, group))

    def test_exact_provider_and_namespaced_ownership(self):
        self.insert()
        self.insert(namespace="role", kind="group", group=2)
        self.insert(provider="other", group=3)
        self.assertEqual(len(self.maps.read("directory")), 2)
        self.assertEqual(self.maps.read("Directory"), [])
        self.assertEqual(self.maps.read("directory")[0]["external_id"], "部门:一")

    def test_native_id_and_subject_unique_constraints(self):
        import pymysql
        self.insert()
        for kwargs in (dict(group=2), dict(provider="other")):
            with self.assertRaises(pymysql.err.IntegrityError):
                self.insert(**kwargs)

    def test_bad_legacy_rows_and_database_failure_never_become_empty_maps(self):
        self.insert(group=-1)
        with self.assertRaises(ContractError) as caught:
            self.maps.read("directory")
        self.assertEqual(caught.exception.status, 503)
        with self.connection.cursor() as cursor:
            cursor.execute("DROP TABLE cf_sso_group_map")
        with self.assertRaises(ContractError):
            self.maps.read("directory")

    def test_ownership_index_drift_is_rejected(self):
        with self.connection.cursor() as cursor:
            cursor.execute("ALTER TABLE cf_sso_group_map DROP INDEX group_map_native")
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection).require_current()

    def test_unresolved_legacy_table_is_preserved_not_implicitly_adopted(self):
        with self.connection.cursor() as cursor:
            cursor.execute("DROP TABLE cf_sso_group_map")
            cursor.execute("DELETE FROM cf_schema_migration WHERE version='006_group_maps'")
            cursor.execute("CREATE TABLE cf_sso_group_map(provider VARCHAR(32),external_id VARCHAR(255),group_id INT) ENGINE=InnoDB")
            cursor.execute("INSERT INTO cf_sso_group_map VALUES('directory','legacy-id',77)")
        with self.assertRaises(MigrationError):
            SchemaRunner(self.connection).apply()
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT provider,external_id,group_id FROM cf_sso_group_map")
            self.assertEqual(cursor.fetchall(), (("directory", "legacy-id", 77),))
        with self.assertRaises(ContractError):
            self.maps.read("directory")

    def test_field_width_native_type_and_prefix_index_drift_rejected(self):
        variants = (
            ("ALTER TABLE cf_sso_group_map MODIFY namespace VARCHAR(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL",
             "ALTER TABLE cf_sso_group_map MODIFY namespace VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL"),
            ("ALTER TABLE cf_sso_group_map MODIFY group_id BIGINT NOT NULL",
             "ALTER TABLE cf_sso_group_map MODIFY group_id INT NOT NULL"),
            ("ALTER TABLE cf_sso_group_map DROP INDEX group_map_subject, ADD UNIQUE KEY group_map_subject(provider,subject_type,namespace,external_id(100))",
             "ALTER TABLE cf_sso_group_map DROP INDEX group_map_subject, ADD UNIQUE KEY group_map_subject(provider,subject_type,namespace,external_id)"),
        )
        for changed, restored in variants:
            with self.subTest(changed=changed):
                with self.connection.cursor() as cursor:
                    cursor.execute(changed)
                try:
                    with self.assertRaises(MigrationError):
                        SchemaRunner(self.connection).require_current()
                finally:
                    with self.connection.cursor() as cursor:
                        cursor.execute(restored)
                SchemaRunner(self.connection).require_current()
