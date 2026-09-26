"""Real SQL prebinding; management authorization/audit are explicit fixtures."""
import json
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.sql_bindings import SQLIdentityBindings
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class SQLBindingsTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.native = "cf_bind_native_" + uuid4().hex
        self.identity = "cf_bind_identity_" + uuid4().hex
        with self.admin.cursor() as cursor:
            cursor.execute("CREATE DATABASE " + self.native)
            cursor.execute("CREATE DATABASE " + self.identity)
            cursor.execute("CREATE TABLE " + self.native + ".EmailUser(email VARCHAR(255) UNIQUE,is_active INT) ENGINE=InnoDB")
            cursor.execute("INSERT INTO " + self.native + ".EmailUser VALUES('actor@example.invalid',1),('other@example.invalid',1)")
            cursor.execute("CREATE TABLE " + self.identity + ".profile_profile(user VARCHAR(254) UNIQUE,login_id VARCHAR(225) UNIQUE) ENGINE=InnoDB")
            cursor.execute("INSERT INTO " + self.identity + ".profile_profile VALUES('actor@example.invalid',NULL),('other@example.invalid',NULL)")
            cursor.execute("CREATE TABLE " + self.identity + ".social_auth_usersocialauth(id BIGINT AUTO_INCREMENT PRIMARY KEY,username VARCHAR(255),provider VARCHAR(32),uid VARCHAR(255),extra_data TEXT,UNIQUE KEY binding(provider,uid)) ENGINE=InnoDB")
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE cf_probe_binding_audit(payload TEXT) ENGINE=InnoDB")
        self.allowed = True
        self.binding = SQLIdentityBindings(self.connection, native_schema=self.native,
            identity_schema=self.identity, directory_provider="directory",
            authorize=lambda *args: self.allowed,
            audit=lambda cursor, event: cursor.execute("INSERT INTO cf_probe_binding_audit VALUES(%s)", (json.dumps(event),)))
        self.request = dict(issuer="https://identity.example.invalid/application/o/cloudfile/",
            subject="employee-sub", user_id="u1", username="actor@example.invalid",
            actor="admin", reason="approved existing account")

    def tearDown(self):
        with self.admin.cursor() as cursor:
            cursor.execute("DROP DATABASE " + self.native)
            cursor.execute("DROP DATABASE " + self.identity)
        super().tearDown()

    def resolve(self):
        return self.binding.resolve(**{key: self.request[key] for key in ("issuer", "subject", "user_id")})

    def test_atomic_binding_resolve_and_retry(self):
        self.assertIsNone(self.resolve())
        self.assertEqual(self.binding.prebind(**self.request), (self.request["username"], True))
        self.assertEqual(self.resolve(), self.request["username"])
        self.assertEqual(self.binding.prebind(**self.request), (self.request["username"], False))
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_probe_binding_audit")
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_authorization_and_audit_failure_do_not_bind(self):
        self.allowed = False
        with self.assertRaises(ContractError) as caught:
            self.binding.prebind(**self.request)
        self.assertEqual(caught.exception.status, 403)
        self.allowed = True
        def fail(cursor, event):
            raise RuntimeError("private audit failure")
        self.binding.audit = fail
        with self.assertRaises(ContractError):
            self.binding.prebind(**self.request)
        self.assertIsNone(self.resolve())
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT login_id FROM " + self.identity + ".profile_profile WHERE user='actor@example.invalid'")
            self.assertIsNone(cursor.fetchone()[0])

    def test_concurrent_prebind_has_one_change_and_one_retry(self):
        import pymysql
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        start = Barrier(2)
        def bind():
            connection = pymysql.connect(**self.options, database=self.database)
            try:
                binding = SQLIdentityBindings(connection, native_schema=self.native,
                    identity_schema=self.identity, directory_provider="directory",
                    authorize=lambda *args: True,
                    audit=lambda cursor, event: cursor.execute("INSERT INTO cf_probe_binding_audit VALUES(%s)", (json.dumps(event),)))
                start.wait(timeout=5)
                return binding.prebind(**self.request)
            finally:
                connection.close()
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(bind) for _ in range(2)]
            results = [future.result(timeout=10) for future in futures]
        self.assertEqual(sorted(changed for username, changed in results), [False, True])
        self.assertTrue(all(username == self.request["username"] for username, changed in results))
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_probe_binding_audit")
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_binding_conflicts_do_not_merge_accounts(self):
        self.binding.prebind(**self.request)
        for changes in (dict(username="other@example.invalid"), dict(user_id="other"), dict(subject="other-sub", username="other@example.invalid")):
            with self.assertRaises(ContractError) as caught:
                self.binding.prebind(**{**self.request, **changes})
            self.assertEqual(caught.exception.status, 409)
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.identity + ".social_auth_usersocialauth SET extra_data='private-invalid-json'")
        with self.assertRaises(ContractError):
            self.resolve()

    def test_disabled_alias_and_damaged_unique_index_rejected(self):
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_active=0 WHERE email='actor@example.invalid'")
        with self.assertRaises(ContractError) as caught:
            self.binding.prebind(**self.request)
        self.assertEqual(caught.exception.status, 403)
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_active=1,email='Actor@example.invalid' WHERE email='actor@example.invalid'")
        with self.assertRaises(ContractError):
            self.binding.prebind(**self.request)
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET email='actor@example.invalid' WHERE email='Actor@example.invalid'")
            cursor.execute("ALTER TABLE " + self.identity + ".social_auth_usersocialauth DROP INDEX binding")
        with self.assertRaises(ContractError):
            self.binding.prebind(**self.request)
