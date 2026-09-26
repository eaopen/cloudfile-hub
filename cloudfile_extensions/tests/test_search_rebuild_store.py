from unittest.mock import Mock, patch
from contextlib import contextmanager
from types import SimpleNamespace
from datetime import datetime, timezone
from uuid import uuid4

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.search.documents import resource_document
from cloudfile_extensions.search.generations import SearchGenerationStore
from cloudfile_extensions.search.initialization import SearchInitializationStore
from cloudfile_extensions.search.rebuild_store import SearchRebuildStore
from cloudfile_extensions.search.rebuild_execution import SearchRebuildExecution
from cloudfile_extensions.search.tasks import MeilisearchTasks
from cloudfile_extensions.search.catchup import SearchCatchupInspector
from cloudfile_extensions.events.outbox import EventWriter
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class RebuildStoreTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        SearchGenerationStore(self.connection).register("g1", "resources_g1")
        initialization = SearchInitializationStore(self.connection)
        for stage, task in (("create", 1), ("settings", 2)):
            initialization.prepare("g1", "resources_g1", stage)
            initialization.transition("g1", "resources_g1", stage, "prepared", "submitting")
            initialization.dispatch("g1", "resources_g1", stage, Mock(return_value=task))
            initialization.transition("g1", "resources_g1", stage, "submitted", "succeeded")
        self.store = SearchRebuildStore(self.connection)
        self.identity = dict(generation="g1", index="resources_g1", repo_id="11111111-1111-4111-8111-111111111111")
        self.start = dict(**self.identity, commit_id="a" * 40, source_sequence="0")

    def test_start_is_idempotent_but_commit_cannot_change(self):
        self.store.start(**self.start)
        self.store.start(**self.start)
        with self.assertRaises(ContractError):
            self.store.start(**{**self.start, "commit_id": "b" * 40})

    def test_capture_uses_native_head_and_resumes_saved_boundary(self):
        held = []
        @contextmanager
        def scope(connection, repo):
            self.assertIs(connection, self.connection)
            held.append(repo)
            try:
                yield
            finally:
                held.pop()
        api = Mock()
        def repo_read(repo):
            self.assertEqual(held, [repo])
            return SimpleNamespace(id=repo, head_cmmt_id="a" * 40)
        api.get_repo.side_effect = repo_read
        with patch("cloudfile_extensions.search.rebuild_store._native_api", return_value=api):
            boundary = self.store.capture_start(**self.identity, capture_scope=scope)
            self.assertEqual(boundary, dict(commit_id="a" * 40, source_sequence="0", state="scanning"))
            self.assertEqual(self.store.capture_start(**self.identity, capture_scope=scope), boundary)
        api.get_repo.assert_called_once()
        self.assertEqual(held, [])

    def test_capture_without_producer_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.capture_start(**self.identity, capture_scope=None)

    def test_frozen_page_is_immutable_and_does_not_advance_directory(self):
        self.store.start(**self.start)
        document = resource_document(dict(repo_id=self.identity["repo_id"], path="/x", kind="file"), source_sequence="0")
        options = dict(**self.identity, path="/", offset=0, next_offset=None, documents=[document])
        digest = self.store.freeze(**options)
        self.assertEqual(self.store.freeze(**options), digest)
        with self.assertRaises(ContractError):
            self.store.freeze(**{**options, "documents": []})
        with self.connection.cursor() as sql:
            sql.execute("SELECT position,state,task_id FROM cf_search_rebuild_directory WHERE generation='g1'")
            self.assertEqual(sql.fetchone(), (0, "pending", None))

    def test_non_child_projection_is_rejected(self):
        self.store.start(**self.start)
        document = resource_document(dict(repo_id=self.identity["repo_id"], path="/nested/x", kind="file"), source_sequence="0")
        with self.assertRaises(ValueError):
            self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[document])

    def test_task_success_atomically_enqueues_child_and_finishes_parent(self):
        self.store.start(**self.start)
        document = resource_document(dict(repo_id=self.identity["repo_id"], path="/child", kind="dir"), source_sequence="0")
        self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[document])
        client = Mock(spec=MeilisearchTasks)
        client.index = "resources_g1"
        client.replace_documents.return_value = 7
        client.task_status.side_effect = ["processing", "succeeded"]
        execution = SearchRebuildExecution(self.store, client)
        options = dict(generation="g1", repo_id=self.identity["repo_id"], path="/")
        self.assertFalse(execution.advance_page(**options))
        with self.connection.cursor() as sql:
            sql.execute("SELECT COUNT(*) FROM cf_search_rebuild_directory WHERE path='/child'")
            self.assertEqual(sql.fetchone()[0], 0)
        self.assertTrue(execution.advance_page(**options))
        client.replace_documents.assert_called_once()
        with self.connection.cursor() as sql:
            sql.execute("SELECT path,state FROM cf_search_rebuild_directory ORDER BY path")
            self.assertEqual(sql.fetchall(), (("/", "done"), ("/child", "ready")))

    def test_unknown_submission_does_not_resend_or_advance(self):
        self.store.start(**self.start)
        document = resource_document(dict(repo_id=self.identity["repo_id"], path="/x", kind="file"), source_sequence="0")
        digest = self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[document])
        self.store.mark_submitting(**self.identity, path="/", payload_hash=digest)
        client = Mock(spec=MeilisearchTasks)
        client.index = "resources_g1"
        with self.assertRaises(ContractError) as caught:
            SearchRebuildExecution(self.store, client).advance_page(generation="g1", repo_id=self.identity["repo_id"], path="/")
        self.assertEqual(caught.exception.code, "SEARCH_SUBMISSION_UNKNOWN")
        client.replace_documents.assert_not_called()

    def test_empty_page_finishes_without_remote_task(self):
        self.store.start(**self.start)
        self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[])
        client = Mock(spec=MeilisearchTasks)
        client.index = "resources_g1"
        self.assertTrue(SearchRebuildExecution(self.store, client).advance_page(generation="g1", repo_id=self.identity["repo_id"], path="/"))
        client.replace_documents.assert_not_called()
        client.task_status.assert_not_called()

    def test_frontier_requires_finished_root_and_keeps_scanned_idempotent(self):
        self.store.start(**self.start)
        value = self.store.next_directory(**self.identity)
        self.assertEqual(value["state"], "ready")
        self.assertEqual(value["reference"]["path"], "/")
        self.assertEqual(value["commit_id"], "a" * 40)
        self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[])
        client = Mock(spec=MeilisearchTasks)
        client.index = "resources_g1"
        execution = SearchRebuildExecution(self.store, client)
        options = dict(generation="g1", repo_id=self.identity["repo_id"])
        self.assertEqual(execution.advance_next(**options)["state"], "page_completed")
        self.assertEqual(execution.advance_next(**options)["state"], "scanned")
        self.assertEqual(execution.advance_next(**options)["state"], "scanned")
        client.replace_documents.assert_not_called()

    def test_unknown_frontier_is_not_skipped(self):
        self.store.start(**self.start)
        document = resource_document(dict(repo_id=self.identity["repo_id"], path="/x", kind="file"), source_sequence="0")
        digest = self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[document])
        self.store.mark_submitting(**self.identity, path="/", payload_hash=digest)
        self.assertEqual(self.store.next_directory(**self.identity)["state"], "submitting")

    def test_catchup_diagnostics_require_scan_and_do_not_publish(self):
        self.store.start(**self.start)
        inspector = SearchCatchupInspector(self.store)
        with self.assertRaises(ContractError):
            inspector.check_batch(**self.identity)
        self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[])
        client = Mock(spec=MeilisearchTasks)
        client.index = "resources_g1"
        SearchRebuildExecution(self.store, client).advance_page(generation="g1", repo_id=self.identity["repo_id"], path="/")
        self.store.next_directory(**self.identity)
        self.assertEqual(inspector.check_batch(**self.identity), dict(state="observed_cutoff_checked", checked_through="0", observed_cutoff="0", pending_event_id=None))
        with self.connection.cursor() as sql:
            sql.execute("SELECT state FROM cf_search_generation WHERE generation='g1'")
            self.assertEqual(sql.fetchone(), ("building",))

    def test_persistent_checkpoint_resumes_fixed_target_not_new_events(self):
        self.store.start(**self.start)
        self.store.freeze(**self.identity, path="/", offset=0, next_offset=None, documents=[])
        client = Mock(spec=MeilisearchTasks)
        client.index = "resources_g1"
        SearchRebuildExecution(self.store, client).advance_page(generation="g1", repo_id=self.identity["repo_id"], path="/")
        self.store.next_directory(**self.identity)
        def append_reads(count):
            self.connection.begin()
            try:
                with self.connection.cursor() as sql:
                    for unused in range(count):
                        EventWriter().append(sql, dict(event_id=str(uuid4()), occurred_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            request_id="read", actor_user_id="employee", actor_kind="user", source="fileserver",
                            action="file.download", result="succeeded", repo_id=self.identity["repo_id"], path="/x", resource_kind="file"))
                self.connection.commit()
            finally:
                self.connection.rollback()
        append_reads(101)
        inspector = SearchCatchupInspector(self.store)
        first = inspector.advance_checkpoint(**self.identity)
        self.assertEqual(first["state"], "batch_checked")
        self.assertNotEqual(first["checked_through"], first["observed_cutoff"])
        scopes = []
        @contextmanager
        def producer_scope(connection, repo):
            self.assertIs(connection, self.connection)
            scopes.append(repo)
            try:
                yield
            finally:
                scopes.pop()
        with self.assertRaises(ContractError) as caught:
            inspector.refresh_target(**self.identity, producer_scope=producer_scope)
        self.assertEqual(caught.exception.code, "SEARCH_CATCHUP_PENDING")
        append_reads(1)
        # A fresh inspector resumes the durable saved target and position.
        second = SearchCatchupInspector(self.store).advance_checkpoint(**self.identity)
        self.assertEqual(second["observed_cutoff"], first["observed_cutoff"])
        self.assertEqual(second["state"], "observed_cutoff_checked")
        self.assertEqual(second["checked_through"], second["observed_cutoff"])
        self.assertEqual(inspector.advance_checkpoint(**self.identity), second)
        refreshed = inspector.refresh_target(**self.identity, producer_scope=producer_scope)
        self.assertEqual(refreshed["state"], "pending")
        self.assertEqual(refreshed["checked_through"], second["checked_through"])
        self.assertGreater(int(refreshed["observed_cutoff"]), int(second["observed_cutoff"]))
        final = inspector.advance_checkpoint(**self.identity)
        self.assertEqual(final["checked_through"], refreshed["observed_cutoff"])
        self.assertEqual(final["state"], "observed_cutoff_checked")
        self.assertEqual(scopes, [])
        with self.assertRaises(ValueError):
            inspector.refresh_target(**self.identity, producer_scope=None)
