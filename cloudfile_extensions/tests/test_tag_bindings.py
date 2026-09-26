"""Real SQL primitives; lifecycle/write authorization is an explicit fixture."""
import hashlib
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tags.bindings import replace_user_tags
from cloudfile_extensions.tags.read import bound_tags, FIELDS
from cloudfile_extensions.tags.write import create_user, patch_user
from cloudfile_extensions.tags.definitions import system_definition
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class TagBindingTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.repo, self.uid = str(uuid4()), str(uuid4())
        self.ref = dict(repo_id=self.repo, path="/parts/a.prt", kind="file")
        self.connection.begin()
        with self.connection.cursor() as cursor:
            cursor.execute("INSERT INTO cf_resource(uid,repo_id,kind,path,path_hash,lifecycle_ref,revision,state,updated_at) VALUES(%s,%s,'file',%s,%s,'lifecycle-1',1,'active',UTC_TIMESTAMP(6))",
                (self.uid, self.repo, self.ref["path"], hashlib.sha256(self.ref["path"].encode()).hexdigest()))
            self.user, _ = create_user(cursor, repo_id=self.repo, value=dict(label="drawing"), actor="u1", request_id="fixture")
            self.system = system_definition(str(uuid4()), provider="source", namespace="category", code="drawing", value={})
            value = self.system
            cursor.execute("INSERT INTO cf_tag(" + FIELDS + ",updated_at) VALUES(" + ",".join(["%s"] * 11) + ",UTC_TIMESTAMP(6))",
                (value["tag_id"], value["kind"], value["provider"], value["namespace"], value["code"], value["label"], None, None, 1, None, str(uuid4())))
            cursor.execute("INSERT INTO cf_tag_binding(resource_uid,tag_id) VALUES(%s,%s)", (self.uid, value["tag_id"]))
        self.connection.commit()

    def replace(self, ids, revision=1):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                result = replace_user_tags(cursor, reference=self.ref, resource_uid=self.uid,
                    lifecycle_ref="lifecycle-1", expected_revision=revision, tag_ids=ids,
                    actor="u1", request_id="fixture")
            self.connection.commit()
            return result
        finally:
            self.connection.rollback()

    def test_atomic_replace_preserves_system_tags_and_noop_revision(self):
        self.assertEqual(self.replace([self.user["tag_id"]]), (2, True))
        self.assertEqual(self.replace([self.user["tag_id"]], 2), (2, False))
        with self.connection.cursor() as cursor:
            values = bound_tags(cursor, resource_uid=self.uid, repo_id=self.repo)
            self.assertEqual([item["kind"] for item in values], ["system", "user"])
        self.assertEqual(self.replace([], 2), (3, True))
        with self.connection.cursor() as cursor:
            self.assertEqual([item["tag_id"] for item in bound_tags(cursor, resource_uid=self.uid, repo_id=self.repo)], [self.system["tag_id"]])

    def test_disabled_new_binding_and_stale_revision_rejected(self):
        self.connection.begin()
        with self.connection.cursor() as cursor:
            patch_user(cursor, repo_id=self.repo, tag_id=self.user["tag_id"], changes=dict(enabled=False),
                if_match=self.user["etag"], actor="u1", request_id="fixture")
        self.connection.commit()
        with self.assertRaises(ContractError) as caught:
            self.replace([self.user["tag_id"]])
        self.assertEqual(caught.exception.code, "TAG_DISABLED")
        with self.assertRaises(ContractError) as caught:
            self.replace([], 2)
        self.assertEqual(caught.exception.code, "RESOURCE_REVISION_CONFLICT")

    def test_system_id_cannot_be_submitted_as_user_binding(self):
        with self.assertRaises(ContractError) as caught:
            self.replace([self.system["tag_id"]])
        self.assertEqual(caught.exception.status, 404)
