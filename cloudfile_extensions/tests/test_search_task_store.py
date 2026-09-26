"""Real isolated SQL tests; no production schema or external index mutation."""
from datetime import datetime, timezone
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.outbox import EventWriter, Outbox
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.search.task_store import SearchTaskStore
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class SearchTaskStoreTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                EventWriter().append(sql, dict(event_id=str(uuid4()), occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    request_id="request", actor_user_id="employee", actor_kind="user", source="hub",
                    action="resource.attributes.updated", result="succeeded", repo_id="11111111-1111-4111-8111-111111111111"))
            self.connection.commit()
        finally:
            self.connection.rollback()
        self.outbox = Outbox(self.connection)
        self.claim = self.outbox.claim("search", "worker", lease_seconds=300)
        self.store = SearchTaskStore(self.connection)

    def state(self):
        with self.connection.cursor() as sql:
            sql.execute("SELECT search_state FROM cf_event_outbox WHERE event_id=%s", (self.claim.event_id,))
            return sql.fetchone()[0]

    def succeeded(self, step, digest):
        self.store.prepare(self.claim, generation="index", step=step, payload_hash=digest)
        self.store.mark_submitting(self.claim, generation="index", step=step)
        self.store.record_task(self.claim, generation="index", step=step, task_id=step)
        self.store.record_succeeded(self.claim, generation="index", step=step)

    def test_incomplete_or_subset_plan_does_not_acknowledge(self):
        self.succeeded(0, "a" * 64)
        self.store.prepare(self.claim, generation="index", step=1, payload_hash="b" * 64)
        for hashes in (["a" * 64], ["a" * 64, "b" * 64]):
            with self.assertRaises(ContractError):
                self.store.complete_event(self.claim, generation="index", payload_hashes=hashes)
            self.assertEqual(self.state(), "running")

    def test_exact_successful_plan_acknowledges_without_resource_ack(self):
        self.succeeded(0, "a" * 64)
        self.store.complete_event(self.claim, generation="index", payload_hashes=["a" * 64])
        self.assertEqual(self.state(), "done")
        self.assertIsNotNone(self.outbox.claim("resource", "resource-worker"))

    def test_unknown_other_generation_blocks_completion(self):
        self.succeeded(0, "a" * 64)
        self.store.prepare(self.claim, generation="old", step=0, payload_hash="b" * 64)
        self.store.mark_submitting(self.claim, generation="old", step=0)
        with self.assertRaises(ContractError) as caught:
            self.store.complete_event(self.claim, generation="index", payload_hashes=["a" * 64])
        self.assertEqual(caught.exception.code, "SEARCH_SUBMISSION_UNKNOWN")
        self.assertEqual(self.state(), "running")
