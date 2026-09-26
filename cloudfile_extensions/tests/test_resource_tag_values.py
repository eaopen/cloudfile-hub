"""Real SQL atomic label saves; authority/lifecycle are explicit test fixtures.

Execution deferred. These cases do not prove native C/session enforcement.
"""
from unittest.mock import Mock, patch
from uuid import uuid4

from cloudfile_extensions.authorization.read import ContentMetadataWriteAuthority
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.store import ResourceStore, ResourceEvidence
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class ResourceTagValuesTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.ref = dict(repo_id=str(uuid4()), path="/file", kind="file")
        self.store = ResourceStore(self.connection, inspector=Mock(), write_guard=Mock(),
            secret=b"fixture-secret-at-least-32-bytes-long", mutation_hook=Mock())
        self.authority = Mock(spec=ContentMetadataWriteAuthority)
        self.authority.actor = "fixture-user"
        self.authority.state = Mock(connection=self.connection)
        self.authority.consume.side_effect = self.consume
        self.evidence = ResourceEvidence("fixture-native-lifecycle")
        self.initial = self.store._snapshot(self.ref, self.evidence, None)["revision"]

    def consume(self, ref, callback):
        # Explicit transaction fixture, not an authorization implementation.
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                result = callback(cursor, ref)
            self.connection.commit()
            return result
        finally:
            self.connection.rollback()

    def save(self, values, revision=None):
        return self.store.replace_user_tags_authorized(self.ref, [],
            expected_revision=revision or self.initial, authority=self.authority,
            lifecycle_reader=lambda cursor, ref: self.evidence,
            request_id="fixture-request", tag_values=values)

    def counts(self):
        with self.connection.cursor() as cursor:
            values = []
            for table in ("cf_resource", "cf_tag", "cf_tag_binding", "cf_event_outbox"):
                cursor.execute("SELECT COUNT(*) FROM " + table)
                values.append(cursor.fetchone()[0])
            return tuple(values)

    def test_first_save_reuse_and_empty_unannotated_resource(self):
        value, changed = self.save([])
        self.assertFalse(changed)
        self.assertIsNone(value["uid"])
        self.assertEqual(self.counts(), (0, 0, 0, 0))
        value, changed = self.save([dict(label=" drawing ", color="#123abc")])
        self.assertTrue(changed)
        self.assertEqual(value["tags"][0]["color"], "#123ABC")
        self.assertEqual(self.counts()[:3], (1, 1, 1))
        again, changed = self.save([dict(label="drawing", color="#FFFFFF")], value["revision"])
        self.assertFalse(changed)
        self.assertEqual(again, value)

    def test_binding_failure_rolls_back_new_definition_resource_and_events(self):
        with patch("cloudfile_extensions.tags.bindings.replace_user_tags", side_effect=RuntimeError("fixture failure")):
            with self.assertRaises(RuntimeError):
                self.save([dict(label="drawing")])
        self.assertEqual(self.counts(), (0, 0, 0, 0))

    def test_stale_condition_precedes_definition_creation(self):
        self.save([dict(label="drawing")])
        before = self.counts()
        with self.assertRaises(ContractError) as raised:
            self.save([dict(label="new-label")])
        self.assertEqual(raised.exception.code, "RESOURCE_REVISION_CONFLICT")
        self.assertEqual(self.counts(), before)

    def test_duplicate_normalized_labels_rejected_before_transaction(self):
        with self.assertRaises(ContractError):
            self.save([dict(label=" e\u0301 "), dict(label="é")])
        self.authority.consume.assert_not_called()
        self.assertEqual(self.counts(), (0, 0, 0, 0))
