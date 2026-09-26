"""Real SQL projection; generation/audit adapters are explicit test fixtures."""
from datetime import datetime, timezone
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

    def test_native_implicit_ancestor_cannot_add_source_absent_department(self):
        self.subject["organization_ancestors"] = []
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
