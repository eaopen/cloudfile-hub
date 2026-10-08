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
        self.assertEqual(self.binding.prebind(**self.request, dry_run=True), (self.request["username"], True))
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

    def test_native_manager_authority_and_real_transactional_audit(self):
        from cloudfile_extensions.identity.management import IdentityManagement
        from cloudfile_extensions.schema.runner import SchemaRunner
        SchemaRunner(self.connection).apply()
        with self.admin.cursor() as cursor:
            cursor.execute("ALTER TABLE " + self.native + ".EmailUser ADD is_staff INT NOT NULL DEFAULT 0")
            cursor.execute("INSERT INTO " + self.native + ".EmailUser VALUES('manager@example.invalid',1,0)")
            cursor.execute("INSERT INTO " + self.identity + ".profile_profile VALUES('manager@example.invalid','admin')")
        management = IdentityManagement(self.connection, native_schema=self.native,
            identity_schema=self.identity, directory_provider="directory",
            actor_user_id="admin", request_id="prebind-test")
        request = {key: value for key, value in self.request.items() if key != "actor"}
        with self.assertRaises(ContractError) as caught:
            management.prebind(**request)
        self.assertEqual(caught.exception.status, 403)
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_staff=1 WHERE email='manager@example.invalid'")
        with self.assertRaises(ContractError):
            management.prebind(**{**request, "reason": "private\nreason"})
        self.assertIsNone(self.resolve())
        self.assertEqual(management.prebind(**request), (request["username"], True))
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT actor_user_id,event_payload FROM cf_audit_event")
            actor, raw = cursor.fetchone()
            self.assertEqual(actor, "admin")
            self.assertEqual(json.loads(raw)["target_user_id"], "u1")
            self.assertEqual(json.loads(raw)["reason"], request["reason"])
            cursor.execute("SELECT COUNT(*) FROM cf_event_outbox")
            self.assertEqual(cursor.fetchone()[0], 1)
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_staff=0 WHERE email='manager@example.invalid'")
        with self.assertRaises(ContractError) as caught:
            management.prebind(**request)
        self.assertEqual(caught.exception.status, 403)

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

    def test_jit_new_identity_atomic_retry_disabled_and_barrier(self):
        from datetime import datetime, timezone
        from unittest.mock import Mock, patch
        from cloudfile_extensions.identity.jit import SQLJITProvisioner
        from cloudfile_extensions.directory.provider import DirectoryProvider
        from cloudfile_extensions.schema.runner import SchemaRunner
        SchemaRunner(self.connection).apply()
        with self.admin.cursor() as cursor:
            cursor.execute("ALTER TABLE " + self.native + ".EmailUser ADD passwd VARCHAR(256),ADD is_staff INT NOT NULL DEFAULT 0,ADD ctime BIGINT")
            cursor.execute("ALTER TABLE " + self.identity + ".profile_profile ADD nickname VARCHAR(64) NOT NULL DEFAULT '',ADD intro TEXT,ADD lang_code TEXT,ADD contact_email VARCHAR(225) UNIQUE,ADD is_manually_set_contact_email TINYINT DEFAULT 0,ADD institution VARCHAR(225),ADD list_in_address_book TINYINT NOT NULL DEFAULT 0")
        transport = Mock()
        transport.get.return_value = dict(userId="new-user", status="active", attributes={}, organizations=[], roles=[],
            etag="fresh", generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        directory = DirectoryProvider("https://directory.example.invalid/v2", authorization=lambda: "Bearer fixture",
                                      attribute_allowlist=(), client=transport)
        jit = SQLJITProvisioner(self.binding, issuer=self.request["issuer"], directory=directory,
                               enabled=True, request_id="jit-test")
        identity = dict(issuer=self.request["issuer"], sub="new-sub", userId="new-user")
        # Every native row rolls back if transactional audit fails.
        with patch("cloudfile_extensions.identity.jit.EventWriter.append", side_effect=RuntimeError("audit down")):
            with self.assertRaises(ContractError):
                jit.ensure(identity)
        self.assertIsNone(self.binding.resolve(issuer=identity["issuer"], subject=identity["sub"], user_id=identity["userId"]))
        committed = self.connection.commit
        def response_lost():
            committed()
            raise RuntimeError("commit acknowledgement lost")
        with patch.object(self.connection, "commit", side_effect=response_lost):
            with self.assertRaises(ContractError):
                jit.ensure(identity)
        username = jit.ensure(identity)
        self.assertTrue(username.endswith("@auth.local"))
        self.assertEqual(jit.ensure(identity), username)
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT passwd,is_staff,is_active FROM " + self.native + ".EmailUser WHERE email=%s", (username,))
            self.assertEqual(cursor.fetchone(), ("!", 0, 1))
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_active=0 WHERE email=%s", (username,))
        with self.assertRaises(ContractError) as caught:
            jit.ensure(identity)
        self.assertEqual(caught.exception.status, 403)
        transport.get.return_value = {**transport.get.return_value, "userId": "blocked-user"}
        jit.state.jobs.submit(actor="admin", actor_kind="user", kind="subject.refresh",
            scope=dict(type="user", provider="directory", external_id="blocked-user"),
            request={}, idempotency_key=uuid4().hex, barrier=True)
        with self.assertRaises(ContractError):
            jit.ensure({**identity, "userId": "blocked-user", "sub": "blocked-sub"})
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_audit_event WHERE operation='identity.created'")
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_scheme_b_employee_name_reuse_collision_and_disabled_account(self):
        from datetime import datetime, timezone
        from unittest.mock import Mock
        from cloudfile_extensions.identity.jit import SQLJITProvisioner
        from cloudfile_extensions.directory.provider import DirectoryProvider
        from cloudfile_extensions.schema.runner import SchemaRunner
        SchemaRunner(self.connection).apply()
        with self.admin.cursor() as cursor:
            cursor.execute("ALTER TABLE " + self.native + ".EmailUser ADD passwd VARCHAR(256),ADD is_staff INT NOT NULL DEFAULT 0,ADD ctime BIGINT")
            cursor.execute("ALTER TABLE " + self.identity + ".profile_profile ADD nickname VARCHAR(64) NOT NULL DEFAULT '',ADD intro TEXT,ADD lang_code TEXT,ADD contact_email VARCHAR(225) UNIQUE,ADD is_manually_set_contact_email TINYINT DEFAULT 0,ADD institution VARCHAR(225),ADD list_in_address_book TINYINT NOT NULL DEFAULT 0")
        transport = Mock()
        def claims(uid, employee):
            transport.get.return_value = dict(userId=uid, status="active", attributes={"employee_no": employee},
                organizations=[], roles=[], etag="fresh",
                generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
            return dict(issuer=self.request["issuer"], sub="sub-" + uid, userId=uid)
        directory = DirectoryProvider("https://directory.example.invalid/v2", authorization=lambda: "Bearer fixture",
                                      attribute_allowlist={"employee_no"}, client=transport)
        jit = SQLJITProvisioner(self.binding, issuer=self.request["issuer"], directory=directory,
                               enabled=True, request_id="scheme-b-test")
        # Employee numbers name only new accounts; UID remains the authority key.
        new_identity = claims("new-uid", "10280993")
        self.assertEqual(jit.ensure(new_identity), "10280993@auth.local")
        self.assertEqual(jit.ensure(new_identity), "10280993@auth.local")
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT login_id FROM " + self.identity + ".profile_profile WHERE user='10280993@auth.local'")
            self.assertEqual(cursor.fetchone(), ("new-uid",))
        # A new UID with the same employee number cannot take over existing files.
        with self.assertRaises(ContractError) as caught:
            jit.ensure(claims("replacement-uid", "10280993"))
        self.assertEqual(caught.exception.status, 409)
        # Existing UID profiles keep their native name and gain only an OIDC binding.
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.identity + ".profile_profile SET login_id='old-uid' WHERE user='actor@example.invalid'")
        old_identity = claims("old-uid", "changed-employee")
        self.assertEqual(jit.ensure(old_identity), "actor@example.invalid")
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM " + self.native + ".EmailUser")
            self.assertEqual(cursor.fetchone()[0], 3)
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_active=0 WHERE email='other@example.invalid'")
            cursor.execute("UPDATE " + self.identity + ".profile_profile SET login_id='disabled-uid' WHERE user='other@example.invalid'")
        with self.assertRaises(ContractError) as caught:
            jit.ensure(claims("disabled-uid", "inactive-employee"))
        self.assertEqual(caught.exception.status, 403)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT operation FROM cf_audit_event")
            self.assertEqual(sorted(row[0] for row in cursor.fetchall()), ["identity.bound", "identity.created"])
        # The system administrator and unsafe employee strings never enter JIT.
        for employee in ("cfadmin", "CFADMIN", "bad@employee", "", "../escape"):
            with self.assertRaises(ContractError):
                jit.ensure(claims("invalid-" + str(len(employee)), employee))
