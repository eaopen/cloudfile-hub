"""Sparse-state transactions against a dedicated, disposable MariaDB database."""

import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.resources.store import ResourceEvidence, ResourceStore
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class ResourceStoreTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.lifecycle = "object-lifecycle-1"
        self.deny_write = False
        self.reference = {"repo_id": "11111111-1111-4111-8111-111111111111", "path": "/parts/model.prt", "kind": "file"}
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE cf_test_event(id INT AUTO_INCREMENT PRIMARY KEY,action VARCHAR(64))")
        self.store = ResourceStore(self.connection, inspector=self.inspect,
                                   write_guard=self.guard,
                                   secret=b"test-resource-secret-at-least-32-bytes", mutation_hook=self.event)

    @contextmanager
    def guard(self, reference, actor):
        # Only a fixture: real lifecycle/ACL fencing is a Server integration gate.
        yield self.inspect(reference, actor, "write")

    def inspect(self, reference, actor, action):
        if self.deny_write and action == "write":
            raise ContractError("PERMISSION_DENIED", "Forbidden", 403)
        return ResourceEvidence(self.lifecycle)

    def event(self, cursor, event):
        cursor.execute("INSERT INTO cf_test_event(action) VALUES(%s)", (event["action"],))

    def count(self, table):
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM " + table)
            return cursor.fetchone()[0]

    def test_read_and_empty_write_never_allocate_rows(self):
        old = self.store.resolve(self.reference, actor="u1")
        self.assertIsNone(old["uid"])
        same, created = self.store.write(self.reference, {"description": ""}, expected_revision=old["revision"], actor="u1")
        self.assertFalse(created)
        self.assertEqual(same, old)
        self.assertEqual(self.count("cf_resource"), 0)
        self.assertEqual(self.count("cf_test_event"), 0)

    def test_first_write_and_stale_condition_are_atomic(self):
        old = self.store.resolve(self.reference, actor="u1")
        current, created = self.store.write(self.reference, {"description": "CAD", "local_open_type": "cad.v1"}, expected_revision=old["revision"], actor="u1")
        self.assertTrue(created)
        self.assertIsNotNone(current["uid"])
        self.assertEqual(self.count("cf_resource"), 1)
        self.assertEqual(self.count("cf_test_event"), 1)
        with self.assertRaises(ContractError) as caught:
            self.store.write(self.reference, {"description": "stale"}, expected_revision=old["revision"], actor="u1")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.store.resolve(self.reference, actor="u1")["description"], "CAD")

    def test_bounded_rows_match_single_reads_and_never_allocate_sparse_uid(self):
        # Real parameterized SQL, including long multibyte paths and sparse misses.
        refs = [{**self.reference, "path": "/路径/" + str(index) + "字" * 400} for index in range(50)]
        for ref in refs[:3]:
            old = self.store.resolve(ref, actor="u1")
            self.store.write(ref, {"description": "CAD"}, expected_revision=old["revision"], actor="u1")
        evidence = ResourceEvidence(self.lifecycle)
        self.connection.begin()
        try:
            with self.connection.cursor() as cursor:
                rows = self.store.resource_rows_many(cursor, refs, [evidence] * len(refs))
                self.assertEqual(rows, [self.store._row(ref, evidence, locking=True) for ref in refs])
                self.assertTrue(all(row is None for row in rows[3:]))
                with self.assertRaises(ValueError):
                    self.store.resource_rows_many(cursor, refs + refs[:1], [evidence] * 51)
                with self.assertRaises(ContractError) as caught:
                    self.store.resource_rows_many(cursor, refs[:1], [ResourceEvidence("reborn")])
                self.assertEqual(caught.exception.code, "PATH_STATE_PENDING")
        finally:
            self.connection.rollback()
        self.assertEqual(self.count("cf_resource"), 3)

    def test_event_failure_rolls_back_metadata(self):
        def unavailable(cursor, event):
            raise RuntimeError("event writer unavailable")
        self.store.mutation_hook = unavailable
        old = self.store.resolve(self.reference, actor="u1")
        with self.assertRaises(RuntimeError):
            self.store.write(self.reference, {"description": "CAD"}, expected_revision=old["revision"], actor="u1")
        self.assertEqual(self.count("cf_resource"), 0)

    def test_delete_recreate_cannot_reuse_empty_or_existing_revision(self):
        old = self.store.resolve(self.reference, actor="u1")
        self.lifecycle = "new-lifecycle-same-content"
        with self.assertRaises(ContractError) as caught:
            self.store.write(self.reference, {"description": "CAD"}, expected_revision=old["revision"], actor="u1")
        self.assertEqual(caught.exception.status, 409)
        current = self.store.resolve(self.reference, actor="u1")
        self.store.write(self.reference, {"description": "CAD"}, expected_revision=current["revision"], actor="u1")
        self.lifecycle = "third-lifecycle"
        with self.assertRaises(ContractError) as caught:
            self.store.resolve(self.reference, actor="u1")
        self.assertEqual(caught.exception.code, "PATH_STATE_PENDING")

    def test_write_permission_is_not_inferred_from_previous_read(self):
        old = self.store.resolve(self.reference, actor="u1")
        self.deny_write = True
        with self.assertRaises(ContractError) as caught:
            self.store.write(self.reference, {"description": "CAD"}, expected_revision=old["revision"], actor="u1")
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(self.count("cf_resource"), 0)

    def test_concurrent_first_writers_allocate_one_row_and_one_event(self):
        import pymysql
        old = self.store.resolve(self.reference, actor="u1")
        rendezvous = Barrier(2)

        def writer(description):
            connection = pymysql.connect(**self.options, database=self.database)
            try:
                store = ResourceStore(connection, inspector=self.inspect, write_guard=self.guard,
                                      secret=self.store.secret, mutation_hook=self.event)
                rendezvous.wait(timeout=5)
                try:
                    return store.write(self.reference, {"description": description},
                                       expected_revision=old["revision"], actor="u1")[1]
                except ContractError as error:
                    return error.status
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(writer, ("first", "second")))
        self.assertCountEqual(results, [True, 409])
        self.assertEqual(self.count("cf_resource"), 1)
        self.assertEqual(self.count("cf_test_event"), 1)

    def test_hash_collision_does_not_alias_distinct_paths(self):
        self.store._hash = lambda path: "a" * 64
        other = {**self.reference, "path": "/parts/other.prt"}
        first = self.store.resolve(self.reference, actor="u1")
        second = self.store.resolve(other, actor="u1")
        a, _ = self.store.write(self.reference, {"description": "A"}, expected_revision=first["revision"], actor="u1")
        b, _ = self.store.write(other, {"description": "B"}, expected_revision=second["revision"], actor="u1")
        self.assertNotEqual(a["uid"], b["uid"])
        self.assertEqual(self.store.resolve(self.reference, actor="u1")["description"], "A")
        self.assertEqual(self.store.resolve(other, actor="u1")["description"], "B")
