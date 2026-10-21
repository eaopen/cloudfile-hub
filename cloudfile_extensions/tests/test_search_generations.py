"""Isolated SQL regressions, intentionally deferred to centralized validation."""
from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.search.generations import SearchGenerationStore
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class SearchGenerationTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = SearchGenerationStore(self.connection)

    def test_identity_cannot_be_rebound_or_recycled(self):
        self.assertEqual(self.store.register("g1", "resources_g1"), "building")
        self.assertEqual(self.store.register("g1", "resources_g1"), "building")
        for generation, index in (("g1", "other"), ("g2", "resources_g1")):
            with self.assertRaises(ContractError):
                self.store.register(generation, index)
        self.store.retire("g1", "resources_g1")
        self.assertEqual(self.store.register("g1", "resources_g1"), "retired")
        with self.assertRaises(ContractError):
            self.store.register("g2", "resources_g1")
        self.assertEqual(self.store.register("g2", "resources_g2"), "building")

    def test_retirement_blocks_locked_dispatch(self):
        self.store.register("g1", "resources_g1")
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                self.store.require_dispatch(sql, "g1", "resources_g1")
        finally:
            self.connection.rollback()
        self.store.retire("g1", "resources_g1")
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                with self.assertRaises(ContractError):
                    self.store.require_dispatch(sql, "g1", "resources_g1")
        finally:
            self.connection.rollback()
