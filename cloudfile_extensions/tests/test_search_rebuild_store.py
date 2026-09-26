from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.search.documents import resource_document
from cloudfile_extensions.search.generations import SearchGenerationStore
from cloudfile_extensions.search.initialization import SearchInitializationStore
from cloudfile_extensions.search.rebuild_store import SearchRebuildStore
from cloudfile_extensions.search.rebuild_execution import SearchRebuildExecution
from cloudfile_extensions.search.tasks import MeilisearchTasks
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
