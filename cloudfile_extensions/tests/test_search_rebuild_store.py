from unittest.mock import Mock

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.search.documents import resource_document
from cloudfile_extensions.search.generations import SearchGenerationStore
from cloudfile_extensions.search.initialization import SearchInitializationStore
from cloudfile_extensions.search.rebuild_store import SearchRebuildStore
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
