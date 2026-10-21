"""Real SQL projection; generation/audit adapters are explicit test fixtures."""
from datetime import datetime, timezone
import json
import os
import unittest
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.directory.project import NativeMembershipProjector
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class ProjectionTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.native = "cf_project_" + uuid4().hex
        self.identity = "cf_profile_" + uuid4().hex
        self.username = "actor@example.invalid"
        self.epoch = uuid4().hex
        self.calls = 0
        self.valid = True
        with self.admin.cursor() as cursor:
            for schema in (self.native, self.identity):
                cursor.execute("CREATE DATABASE " + schema)
            cursor.execute("CREATE TABLE " + self.native + ".EmailUser(email VARCHAR(255) PRIMARY KEY,is_active INT) ENGINE=InnoDB")
            cursor.execute("INSERT INTO " + self.native + ".EmailUser VALUES(%s,1)", (self.username,))
            cursor.execute("CREATE TABLE " + self.identity + ".profile_profile(user VARCHAR(254) UNIQUE,login_id VARCHAR(225) UNIQUE) ENGINE=InnoDB")
            cursor.execute("INSERT INTO " + self.identity + ".profile_profile VALUES(%s,'u1')", (self.username,))
            cursor.execute("CREATE TABLE " + self.native + ".`Group`(group_id BIGINT PRIMARY KEY,parent_group_id INT) ENGINE=InnoDB")
            cursor.execute("INSERT INTO " + self.native + ".`Group` VALUES(1,-1),(2,1),(3,0),(4,0),(5,0),(6,0)")
            cursor.execute("CREATE TABLE " + self.native + ".GroupStructure(group_id INT PRIMARY KEY,path VARCHAR(1024)) ENGINE=InnoDB")
            cursor.execute("INSERT INTO " + self.native + ".GroupStructure VALUES(1,'1'),(2,'1, 2')")
            cursor.execute("CREATE TABLE " + self.native + ".GroupUser(id BIGINT AUTO_INCREMENT PRIMARY KEY,group_id BIGINT,user_name VARCHAR(255),is_staff TINYINT,UNIQUE KEY member(group_id,user_name),INDEX username(user_name)) ENGINE=InnoDB")
            for group, staff in ((4, 0), (5, 0), (6, 1)):
                cursor.execute("INSERT INTO " + self.native + ".GroupUser(group_id,user_name,is_staff) VALUES(%s,%s,%s)", (group, self.username, staff))
        with self.connection.cursor() as cursor:
            for group, kind, namespace, external, provider in (
                    (1, "dept", "directory", "root", "directory"), (2, "dept", "directory", "child", "directory"),
                    (3, "group", "role", "r1", "directory"), (4, "group", "role", "old", "directory"),
                    (5, "group", "role", "other", "other")):
                cursor.execute("INSERT INTO cf_sso_group_map(provider,subject_type,namespace,external_id,group_id,name) VALUES(%s,%s,%s,%s,%s,'display-only')",
                               (provider, kind, namespace, external, group))
            cursor.execute("CREATE TABLE cf_probe_member_audit(user_id VARCHAR(225)) ENGINE=InnoDB")
        def generation(user_id, epoch):
            self.calls += 1
            if not self.valid or user_id != "u1" or epoch != self.epoch:
                raise ContractError("SUBJECT_UNAVAILABLE", "Subject generation is unavailable", 503)
        def audit(cursor, event):
            cursor.execute("INSERT INTO cf_probe_member_audit VALUES(%s)", (event["actor"],))
        self.projector = NativeMembershipProjector(self.connection, native_schema=self.native,
                identity_schema=self.identity, provider="directory", assert_generation=generation, audit_hook=audit)
        self.subject = dict(userId="u1", status="active", attributes={},
                            organizations=[dict(namespace="directory", external_id="child", is_primary=True)],
                            organization_ancestors=[dict(namespace="directory", external_id="root")],
                            roles=[dict(namespace="role", external_id="r1")], etag="one",
                            generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))

    def tearDown(self):
        with self.admin.cursor() as cursor:
            cursor.execute("DROP DATABASE " + self.native)
            cursor.execute("DROP DATABASE " + self.identity)
        super().tearDown()

    def apply(self):
        return self.projector.apply(self.subject, self.epoch, native_username=self.username)

    def memberships(self):
        with self.admin.cursor() as cursor:
            cursor.execute("SELECT group_id,is_staff FROM " + self.native + ".GroupUser ORDER BY group_id")
            return cursor.fetchall()

    def test_apply_readback_retry_and_unmanaged_staff_preserved(self):
        plan = self.apply()
        self.assertEqual((plan.add, plan.remove), ((1, 2, 3), (4,)))
        self.assertEqual(self.memberships(), ((1, 0), (2, 0), (3, 0), (5, 0), (6, 1)))
        plan = self.apply()
        self.assertEqual((plan.add, plan.remove), ((), ()))
        self.assertEqual(self.calls, 4)

    def test_refresh_guard_lost_scope_cannot_supply_owner_proof(self):
        from cloudfile_extensions.directory.coordinator import SQLRefreshGuard
        from cloudfile_extensions.jobs.authority import canonical_scope, lock_name
        guard = SQLRefreshGuard(self.connection, provider="directory")
        scope = dict(type="user", provider="directory", external_id="u1")
        with self.assertRaises(ContractError):
            with guard("u1", self.epoch, phase="publish") as proof:
                with self.connection.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name(self.database, canonical_scope(scope)),))
                    self.assertEqual(cursor.fetchone()[0], 1)
                proof()
        self.assertFalse(self.connection.open)

    def test_refresh_guard_serializes_competing_generations(self):
        import pymysql
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from cloudfile_extensions.directory.coordinator import SQLRefreshGuard
        attempting, entered = Event(), Event()
        def successor():
            connection = pymysql.connect(**self.options, database=self.database)
            try:
                attempting.set()
                with SQLRefreshGuard(connection, provider="directory")("u1", uuid4().hex, phase="begin") as proof:
                    proof()
                    entered.set()
            finally:
                connection.close()
        with ThreadPoolExecutor(max_workers=1) as executor:
            with SQLRefreshGuard(self.connection, provider="directory")("u1", self.epoch, phase="publish") as proof:
                future = executor.submit(successor)
                self.assertTrue(attempting.wait(1))
                self.assertFalse(entered.wait(0.1))
                proof()
            future.result(timeout=5)
        self.assertTrue(entered.is_set())

    def test_current_sql_subject_state_and_durable_barriers(self):
        from cloudfile_extensions.directory.native_state import NativeSubjectState
        state = NativeSubjectState(self.connection, native_schema=self.native,
                                   identity_schema=self.identity, provider="directory")
        self.assertEqual(state.username("u1"), self.username)
        self.assertTrue(state.account_active("u1"))
        self.assertFalse(state.account_active("unbound"))
        self.assertFalse(state.barrier_active("directory", "u1"))
        scope = dict(type="provider", provider="directory", external_id="directory")
        job, _ = state.jobs.submit(actor="admin", actor_kind="user", kind="subject.refresh",
                                   scope=scope, request={}, idempotency_key=uuid4().hex, barrier=True)
        self.assertTrue(state.barrier_active("directory", "u1"))
        with self.assertRaises(ContractError):
            with state.refresh_guard("u1", self.epoch, phase="publish"):
                self.fail("fenced refresh entered")
        # Failure transition is permitted, but never clears the durable barrier.
        with state.refresh_guard("u1", self.epoch, phase="fail") as proof:
            proof()
        self.assertTrue(state.barrier_active("directory", "u1"))
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_active=0")
        self.assertFalse(state.account_active("u1"))
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.identity + ".profile_profile SET login_id='U1'")
        with self.assertRaises(ContractError):
            state.username("u1")

    def test_disabled_snapshot_removes_owned_members_without_adding(self):
        self.subject.update(status="disabled", organizations=[], organization_ancestors=[], roles=[])
        self.assertEqual(self.apply().remove, (4,))
        self.assertEqual(self.memberships(), ((5, 0), (6, 1)))

    def test_account_and_business_binding_rechecked_on_every_projection(self):
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_active=0")
        with self.assertRaises(ContractError):
            self.apply()
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".EmailUser SET is_active=1")
            cursor.execute("UPDATE " + self.identity + ".profile_profile SET login_id='employee-1'")
        with self.assertRaises(ContractError):
            self.apply()
        self.assertEqual(self.memberships(), ((4, 0), (5, 0), (6, 1)))

    def test_lost_generation_after_effects_rolls_back_everything(self):
        original = self.projector.assert_generation
        def generation(user, epoch):
            if self.calls == 1:
                self.valid = False
            original(user, epoch)
        self.projector.assert_generation = generation
        with self.assertRaises(ContractError):
            self.apply()
        self.assertEqual(self.memberships(), ((4, 0), (5, 0), (6, 1)))
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_probe_member_audit")
            self.assertEqual(cursor.fetchone()[0], 0)

    @unittest.skipUnless(os.environ.get("CF_TEST_REDIS_PORT"), "requires isolated Redis")
    def test_preparation_assembly_real_account_barrier_members_and_audit(self):
        import redis
        from cloudfile_extensions.directory.preparation import SubjectPreparation
        from cloudfile_extensions.directory.provider import DirectoryProvider
        from unittest.mock import Mock
        client = redis.Redis(host=os.environ.get("CF_TEST_REDIS_HOST", "127.0.0.1"),
                             port=int(os.environ["CF_TEST_REDIS_PORT"]))
        transport = Mock()
        transport.get.return_value = self.subject
        directory = DirectoryProvider("https://directory.example.invalid/context/v2",
            authorization=lambda: "Bearer fixture", attribute_allowlist=(), client=transport,
            require_organization_ancestors=True)
        runtime = SubjectPreparation(self.connection, client, provider_id="directory", directory=directory,
            native_schema=self.native, identity_schema=self.identity, actor_user_id="u1",
            request_id="test-request", prefix="cf:test:" + uuid4().hex + ":")
        try:
            with self.assertRaises(ContractError) as caught:
                runtime.prepare("u2", trigger="login")
            self.assertEqual(caught.exception.status, 403)
            self.assertEqual(transport.get.call_count, 0)
            value = runtime.prepare("u1", trigger="login")
            self.assertEqual(value["status"], "ready")
            self.assertEqual(self.memberships(), ((1, 0), (2, 0), (3, 0), (5, 0), (6, 1)))
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT actor_user_id,operation,source,event_payload FROM cf_audit_event")
                rows = cursor.fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][:3], ("u1", "subject.memberships", "directory"))
                self.assertEqual(json.loads(rows[0][3])["subject_revision"], value["context_epoch"])
                cursor.execute("SELECT COUNT(*) FROM cf_event_outbox")
                self.assertEqual(cursor.fetchone()[0], 1)
            runtime.prepare("u1", trigger="login")
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM cf_audit_event")
                self.assertEqual(cursor.fetchone()[0], 1)
            # Source read remains a transport fixture. Add a real barrier during
            # that read: publication guard must reject before native mutation.
            def fenced_fetch(*args, **kwargs):
                runtime.state.jobs.submit(actor="admin", actor_kind="user", kind="subject.refresh",
                    scope=dict(type="user", provider="directory", external_id="u1"),
                    request={}, idempotency_key=uuid4().hex, barrier=True)
                return {**self.subject, "roles": []}
            transport.get.side_effect = fenced_fetch
            with self.assertRaises(ContractError):
                runtime.prepare("u1", trigger="force")
            self.assertEqual(self.memberships(), ((1, 0), (2, 0), (3, 0), (5, 0), (6, 1)))
            self.assertTrue(runtime.state.barrier_active("directory", "u1"))
        finally:
            client.delete(*runtime.contexts._keys("u1"))
            client.close()

    @unittest.skipUnless(os.environ.get("CF_TEST_REDIS_PORT"), "requires isolated Redis")
    def test_real_refresh_guard_projection_and_ready(self):
        import redis
        from cloudfile_extensions.directory.contexts import SubjectContexts
        from cloudfile_extensions.directory.native_state import NativeSubjectState
        from cloudfile_extensions.jobs.authority import canonical_scope, lock_name
        client = redis.Redis(host=os.environ.get("CF_TEST_REDIS_HOST", "127.0.0.1"),
                             port=int(os.environ["CF_TEST_REDIS_PORT"]))
        scope = dict(type="user", provider="directory", external_id="u1")
        def fetch(user):
            # Source I/O must not hold the SQL authority lock.
            with self.admin.cursor() as cursor:
                cursor.execute("SELECT IS_USED_LOCK(%s)", (lock_name(self.database, canonical_scope(scope)),))
                self.assertIsNone(cursor.fetchone()[0])
            return self.subject
        state = NativeSubjectState(self.connection, native_schema=self.native,
                                   identity_schema=self.identity, provider="directory")
        contexts = SubjectContexts(client, provider_id="directory", fetch=fetch,
                attribute_allowlist=(), account_active=state.account_active,
                barrier_active=state.barrier_active,
                refresh_guard=state.refresh_guard,
                project=lambda subject, epoch: self.projector.apply(subject, epoch, native_username=state.username(subject["userId"])),
                prefix="cf:test:" + uuid4().hex + ":", jitter=lambda: 0)
        self.projector.assert_generation = contexts.assert_generation
        try:
            value = contexts.get("u1", trigger="login")
            self.assertEqual(value["status"], "ready")
            self.assertEqual(self.memberships(), ((1, 0), (2, 0), (3, 0), (5, 0), (6, 1)))
            self.assertEqual(contexts.get("u1"), value)
            with self.admin.cursor() as cursor:
                cursor.execute("SELECT IS_USED_LOCK(%s)", (lock_name(self.database, canonical_scope(scope)),))
                self.assertIsNone(cursor.fetchone()[0])
        finally:
            client.delete(*contexts._keys("u1"))
            client.close()

    @unittest.skipUnless(os.environ.get("CF_TEST_REDIS_PORT"), "requires isolated Redis")
    def test_real_redis_generation_loss_rolls_back_native_sql(self):
        import redis
        from contextlib import nullcontext
        from cloudfile_extensions.directory.contexts import SubjectContexts
        client = redis.Redis(host=os.environ.get("CF_TEST_REDIS_HOST", "127.0.0.1"),
                             port=int(os.environ["CF_TEST_REDIS_PORT"]))
        contexts = SubjectContexts(client, provider_id="directory", fetch=lambda user: self.subject,
                                  attribute_allowlist=(), account_active=lambda user: True,
                                  barrier_active=lambda provider, user: False,
                                  refresh_guard=lambda *args, **kwargs: nullcontext(),
                                  project=lambda *args: None, prefix="cf:test:" + uuid4().hex + ":")
        key, lease = contexts._keys("u1")
        pending = dict(userId="u1", status="refreshing", context_epoch=self.epoch,
                       expires_at=contexts.clock() + 1800)
        original_audit = self.projector.audit
        try:
            client.set(key, json.dumps(pending), ex=1800)
            client.set(lease, self.epoch, ex=30)
            self.projector.assert_generation = contexts.assert_generation
            def lose_lease(cursor, event):
                original_audit(cursor, event)
                client.delete(lease)
            self.projector.audit = lose_lease
            with self.assertRaises(ContractError):
                self.apply()
            self.assertEqual(self.memberships(), ((4, 0), (5, 0), (6, 1)))
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM cf_probe_member_audit")
                self.assertEqual(cursor.fetchone()[0], 0)
            client.set(lease, self.epoch, ex=30)
            self.projector.audit = original_audit
            self.assertEqual(self.apply().add, (1, 2, 3))
        finally:
            client.delete(key, lease)
            client.close()

    def test_native_implicit_ancestor_cannot_add_source_absent_department(self):
        self.subject["organization_ancestors"] = []
        with self.assertRaises(ContractError):
            self.apply()
        self.assertEqual(self.memberships(), ((4, 0), (5, 0), (6, 1)))

    def test_duplicate_structure_rows_cannot_hide_missing_department(self):
        with self.admin.cursor() as cursor:
            cursor.execute("ALTER TABLE " + self.native + ".GroupStructure DROP PRIMARY KEY")
            cursor.execute("DELETE FROM " + self.native + ".GroupStructure WHERE group_id=2")
            cursor.execute("INSERT INTO " + self.native + ".GroupStructure VALUES(1,'1')")
        with self.assertRaises(ContractError):
            self.apply()
        self.assertEqual(self.memberships(), ((4, 0), (5, 0), (6, 1)))

    def test_owned_staff_delegation_and_native_username_alias_rejected(self):
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".GroupUser SET is_staff=1 WHERE group_id=4")
        with self.assertRaises(ContractError):
            self.apply()
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE " + self.native + ".GroupUser SET is_staff=0,user_name='Actor@example.invalid' WHERE group_id=4")
        with self.assertRaises(ContractError):
            self.apply()

    def test_nontransactional_membership_table_rejected_without_effect(self):
        with self.admin.cursor() as cursor:
            # MyISAM has a 1000-byte key limit; narrow only this owned fixture
            # before engine conversion, keeping all test usernames intact.
            cursor.execute("ALTER TABLE " + self.native + ".GroupUser MODIFY user_name VARCHAR(200)")
            cursor.execute("ALTER TABLE " + self.native + ".GroupUser ENGINE=MyISAM")
        with self.assertRaises(ContractError):
            self.apply()
        self.assertEqual(self.memberships(), ((4, 0), (5, 0), (6, 1)))

    def test_killed_projection_connection_rolls_back_native_effects(self):
        def kill(cursor, event):
            cursor.execute("SELECT CONNECTION_ID()")
            owner = cursor.fetchone()[0]
            # Only this test's owned connection is terminated.
            with self.admin.cursor() as admin:
                admin.execute("KILL CONNECTION " + str(int(owner)))
        self.projector.audit = kill
        with self.assertRaises(ContractError):
            self.apply()
        self.assertEqual(self.memberships(), ((4, 0), (5, 0), (6, 1)))
