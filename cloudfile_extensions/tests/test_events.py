"""SQL atomic facts, legacy audit preservation and independent consumer leases."""
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import EventWriter, Outbox
from cloudfile_extensions.resources.store import ResourceEvidence, ResourceStore
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class EventStoreTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.writer = EventWriter()
        self.outbox = Outbox(self.connection)
        self.event = {"event_id": str(uuid4()), "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                      "request_id": "request-1", "actor_user_id": "u1", "actor_kind": "user", "source": "hub",
                      "action": "resource.attributes.updated", "result": "succeeded",
                      "repo_id": "11111111-1111-4111-8111-111111111111", "path": "/parts/model.prt", "revision": "1"}

    def append(self, event=None):
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                result = self.writer.append(cursor, self.event if event is None else event)
            self.connection.commit()
            return result
        except Exception:
            self.connection.rollback()
            raise

    def count(self, table):
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM " + table)
            return cursor.fetchone()[0]

    def test_event_identity_retries_are_idempotent_but_different_facts_conflict(self):
        one = self.append()
        self.assertEqual(self.append(), one)
        self.assertEqual(self.count("cf_audit_event"), 1)
        self.assertEqual(self.count("cf_event_outbox"), 1)
        with self.assertRaises(ContractError):
            self.append({**self.event, "path": "/different"})
        with self.assertRaises(ContractError):
            self.append({key: value for key, value in self.event.items() if key != "revision"})

    def test_autocommit_event_append_is_rejected_before_any_write(self):
        with self.connection.cursor() as cursor:
            with self.assertRaises(RuntimeError):
                self.writer.append(cursor, self.event)
        self.assertEqual(self.count("cf_audit_event"), 0)
        self.assertEqual(self.count("cf_event_outbox"), 0)

    def test_real_resource_hook_audit_and_outbox_commit_or_rollback_together(self):
        @contextmanager
        def guard(reference, actor):
            yield ResourceEvidence("lifecycle-1")
        reference = {"repo_id": self.event["repo_id"], "path": self.event["path"], "kind": "file"}
        hook = self.writer.resource_hook(request_id="request-1")
        store = ResourceStore(self.connection, inspector=lambda *args: ResourceEvidence("lifecycle-1"),
                              write_guard=guard, secret=b"test-secret-with-at-least-32-bytes", mutation_hook=hook)
        old = store.resolve(reference, actor="u1")
        store.write(reference, {"description": "CAD"}, expected_revision=old["revision"], actor="u1")
        self.assertEqual(self.count("cf_audit_event"), 1)
        self.assertEqual(self.count("cf_event_outbox"), 1)
        current = store.resolve(reference, actor="u1")
        def fail_after_append(cursor, event):
            hook(cursor, event)
            raise RuntimeError("simulated rollback")
        store.mutation_hook = fail_after_append
        with self.assertRaises(RuntimeError):
            store.write(reference, {"description": "changed"}, expected_revision=current["revision"], actor="u1")
        self.assertEqual(store.resolve(reference, actor="u1")["description"], "CAD")
        self.assertEqual(self.count("cf_audit_event"), 1)
        self.assertEqual(self.count("cf_event_outbox"), 1)

    def test_consumers_acknowledge_independently_and_search_failure_preserves_audit(self):
        self.append()
        resource = self.outbox.claim("resource", "worker-1")
        search = self.outbox.claim("search", "worker-2")
        self.outbox.acknowledge(resource)
        self.outbox.retry_later(search, code="INDEX_UNAVAILABLE", delay_seconds=1)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT audit_state,resource_state,search_state FROM cf_event_outbox")
            self.assertEqual(cursor.fetchone(), ("done", "done", "queued"))
        self.assertEqual(self.count("cf_audit_event"), 1)
        self.assertIsNone(self.outbox.claim("resource", "worker-3"))

    def test_expired_consumer_cannot_ack_or_change_new_owner_progress(self):
        self.append()
        old = self.outbox.claim("search", "old-worker")
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE cf_event_outbox SET search_expiry=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))")
        new = self.outbox.claim("search", "new-worker")
        self.assertEqual(new.epoch, old.epoch + 1)
        for operation in (lambda: self.outbox.acknowledge(old), lambda: self.outbox.retry_later(old, code="FAILED")):
            with self.assertRaises(ContractError) as caught:
                operation()
            self.assertEqual(caught.exception.code, "WORKER_LEASE_LOST")
        self.outbox.acknowledge(new)

    def test_credentials_unknown_fields_and_oversize_event_are_not_logged(self):
        for event in ({**self.event, "token": "do-not-store"}, {**self.event, "bytes_sent": True},
                      {**self.event, "request_id": "x" * 256}):
            with self.assertRaises(ContractError):
                self.append(event)
        self.assertEqual(self.count("cf_audit_event"), 0)
        self.assertEqual(self.count("cf_event_outbox"), 0)


class LegacyAuditUpgradeTest(DatabaseTestCase):
    def test_actual_v01_table_shape_and_history_are_preserved_without_fabricating_identity(self):
        runner = SchemaRunner(self.connection)
        audit = next(migration for migration in runner.migrations if migration.version == "004_audit")
        with self.connection.cursor() as cursor:
            cursor.execute(audit.steps[0]["sql"])
            cursor.execute("INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at) "
                           "VALUES('','tag','old-tag','update','legacy@example.com','api','success','2026-01-01 00:00:00')")
        runner.apply()
        runner.require_current()
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT operator,source,schema_version,actor_user_id,event_id,recorded_at FROM cf_audit_event")
            self.assertEqual(cursor.fetchone(), ("legacy@example.com", "api", 0, None, None, None))
