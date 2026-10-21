"""Actual cross-schema SQL; management/audit adapters are explicit fixtures."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.provision import RoleGroupProvisioner
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class GroupProvisionTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.native = "cf_groups_" + uuid4().hex
        with self.admin.cursor() as cursor:
            cursor.execute("CREATE DATABASE " + self.native)
            cursor.execute("CREATE TABLE " + self.native + ".`Group`(group_id BIGINT PRIMARY KEY AUTO_INCREMENT,group_name VARCHAR(255),creator_name VARCHAR(255),timestamp BIGINT,type VARCHAR(32),parent_group_id INT) ENGINE=InnoDB")
            cursor.execute("CREATE TABLE " + self.native + ".GroupStructure(id BIGINT PRIMARY KEY AUTO_INCREMENT,group_id INT UNIQUE,path VARCHAR(1024)) ENGINE=InnoDB")
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE cf_probe_group_audit(group_id INT PRIMARY KEY) ENGINE=InnoDB")
        self.writer = self.writer_for(self.connection)
        self.request = dict(actor="admin-business-id", provider="directory", namespace="role", external_id="r1", name="Shared display name")

    def tearDown(self):
        with self.admin.cursor() as cursor:
            cursor.execute("DROP DATABASE " + self.native)
        super().tearDown()

    def writer_for(self, connection):
        @contextmanager
        def guard(actor, provider):
            yield
        def audit(cursor, event):
            cursor.execute("INSERT INTO cf_probe_group_audit VALUES(%s)", (event["group_id"],))
        return RoleGroupProvisioner(connection, native_schema=self.native, management_guard=guard, audit_hook=audit)

    def counts(self):
        with self.connection.cursor() as cursor:
            result = []
            for table in (self.native + ".`Group`", "cf_sso_group_map", "cf_probe_group_audit"):
                cursor.execute("SELECT COUNT(*) FROM " + table)
                result.append(cursor.fetchone()[0])
            return tuple(result)

    def test_atomic_create_retry_and_manual_names_are_not_adopted(self):
        with self.admin.cursor() as cursor:
            cursor.execute("INSERT INTO " + self.native + ".`Group`(group_name,parent_group_id) VALUES(%s,0)", (self.request["name"],))
        group, created = self.writer.ensure(**self.request)
        self.assertTrue(created)
        self.assertNotEqual(group, 1)
        self.assertEqual(self.writer.ensure(**self.request), (group, False))
        self.assertEqual(self.counts(), (2, 1, 1))

    def test_audit_failure_rolls_back_native_group_and_mapping(self):
        def fail(cursor, event):
            raise RuntimeError("private database detail")
        self.writer.audit = fail
        with self.assertRaises(ContractError) as caught:
            self.writer.ensure(**self.request)
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn("private", caught.exception.message)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_commit_response_loss_retry_does_not_create_another_group(self):
        original = self.connection.commit
        def lost():
            original()
            raise RuntimeError("response lost after committed transaction")
        with patch.object(self.connection, "commit", side_effect=lost):
            with self.assertRaises(ContractError):
                self.writer.ensure(**self.request)
        group, created = self.writer.ensure(**self.request)
        self.assertFalse(created)
        self.assertGreater(group, 0)
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_nontransactional_native_table_rejected_before_write(self):
        with self.admin.cursor() as cursor:
            cursor.execute("ALTER TABLE " + self.native + ".`Group` ENGINE=MyISAM")
        with self.assertRaises(ContractError):
            self.writer.ensure(**self.request)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_management_denial_has_no_native_or_mapping_effect(self):
        @contextmanager
        def denied(actor, provider):
            raise ContractError("FORBIDDEN", "Management permission is required", 403)
            yield
        self.writer.guard = denied
        with self.assertRaises(ContractError) as caught:
            self.writer.ensure(**self.request)
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_department_root_child_and_retry_keep_native_structure(self):
        root, created = self.writer.ensure_department(**self.request)
        self.assertTrue(created)
        child = {**self.request, "external_id": "child", "parent": "r1"}
        group, created = self.writer.ensure_department(**child)
        self.assertTrue(created)
        self.assertEqual(self.writer.ensure_department(**child), (group, False))
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT path FROM " + self.native + ".GroupStructure WHERE group_id=%s", (group,))
            self.assertEqual(cursor.fetchone()[0], f"{root}, {group}")
        self.assertEqual(self.counts(), (2, 2, 2))

    def test_missing_alias_parent_and_reparenting_rejected(self):
        with self.assertRaises(ContractError):
            self.writer.ensure_department(**self.request, parent="missing")
        self.writer.ensure_department(**self.request)
        with self.assertRaises(ContractError):
            self.writer.ensure_department(**{**self.request, "external_id": "child"}, parent="r1 ")
        with self.assertRaises(ContractError):
            self.writer.ensure_department(**self.request, parent="missing")
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_department_audit_failure_rolls_back_structure_too(self):
        def fail(cursor, event):
            raise RuntimeError("failed audit")
        self.writer.audit = fail
        with self.assertRaises(ContractError):
            self.writer.ensure_department(**self.request)
        self.assertEqual(self.counts(), (0, 0, 0))
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM " + self.native + ".GroupStructure")
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_department_structure_drift_and_nontransactional_table_rejected(self):
        root, _ = self.writer.ensure_department(**self.request)
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".GroupStructure SET path='999' WHERE group_id=%s", (root,))
        with self.assertRaises(ContractError):
            self.writer.ensure_department(**{**self.request, "external_id": "child"}, parent="r1")
        with self.admin.cursor() as cursor:
            cursor.execute("ALTER TABLE " + self.native + ".GroupStructure ENGINE=MyISAM")
        with self.assertRaises(ContractError):
            self.writer.ensure_department(**{**self.request, "external_id": "another"})
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_deleted_or_repurposed_native_group_is_not_recreated(self):
        group, _ = self.writer.ensure(**self.request)
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".`Group` SET parent_group_id=-1 WHERE group_id=%s", (group,))
        with self.assertRaises(ContractError):
            self.writer.ensure(**self.request)
        with self.admin.cursor() as cursor:
            cursor.execute("DELETE FROM " + self.native + ".`Group` WHERE group_id=%s", (group,))
        with self.assertRaises(ContractError):
            self.writer.ensure(**self.request)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_concurrent_creation_has_one_group_mapping_and_audit(self):
        import pymysql
        other = pymysql.connect(**self.options, database=self.database)
        try:
            second = self.writer_for(other)
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.writer.ensure, **self.request)
                next_result = pool.submit(second.ensure, **self.request)
                results = (first.result(timeout=10), next_result.result(timeout=10))
            self.assertEqual(results[0][0], results[1][0])
            self.assertEqual(sum(created for _, created in results), 1)
            self.assertEqual(self.counts(), (1, 1, 1))
        finally:
            other.close()
