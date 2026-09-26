"""Actual SQL scope ownership; these are not native permission proofs."""

import time
from unittest.mock import patch

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.jobs.authority import canonical_scope, lock_name, scope_locks
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AuthorityTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        import pymysql
        self.other = pymysql.connect(**self.options, database=self.database)
        self.user = {"type": "user", "provider": "directory", "external_id": "员工:a:b"}
        self.repo = {"type": "repo", "provider": "cloudfile", "external_id": "r1"}

    def tearDown(self):
        self.other.close()
        super().tearDown()

    def test_scope_encoding_namespace_and_schema_are_unambiguous(self):
        one = lock_name(self.database, canonical_scope(self.user))
        self.assertEqual(len(one), 64)
        self.assertNotEqual(one, lock_name(self.database + "x", canonical_scope(self.user)))
        self.assertNotEqual(one, lock_name(self.database, canonical_scope({**self.user, "namespace": "x"})))
        with self.assertRaises(ValueError):
            lock_name("bad\nschema", canonical_scope(self.user))

    def test_duplicate_and_nested_scopes_release_only_own_acquisition(self):
        with scope_locks(self.connection, [self.repo, self.user, self.user], timeout=0):
            with scope_locks(self.connection, [self.user], timeout=0):
                pass
            with self.assertRaises(ContractError) as caught:
                with scope_locks(self.other, [self.user], timeout=0):
                    self.fail("second connection acquired live scope")
            self.assertEqual(caught.exception.code, "AUTHORITY_BUSY")
        with scope_locks(self.other, [self.user, self.repo], timeout=0):
            pass

    def test_partial_acquisition_failure_releases_preceding_scope(self):
        with scope_locks(self.other, [self.repo], timeout=0):
            with self.assertRaises(ContractError):
                with scope_locks(self.connection, [self.repo, self.user], timeout=0):
                    self.fail("repository contention was ignored")
            # User is ordered before repo and was released after repo failure.
            with scope_locks(self.other, [self.user], timeout=0):
                pass

    def test_scope_acquisition_shares_one_deadline(self):
        with scope_locks(self.other, [self.repo], timeout=0):
            started = time.monotonic()
            # Simulate elapsed time between scope acquisitions. The real SQL
            # repo lock remains held: exhausted budget must be nonblocking.
            with patch("cloudfile_extensions.jobs.authority.time.monotonic", side_effect=[100, 104, 106]):
                with self.assertRaises(ContractError) as caught:
                    with scope_locks(self.connection, [self.user, self.repo], timeout=5):
                        self.fail("contended scope acquired")
            self.assertEqual(caught.exception.code, "AUTHORITY_BUSY")
            self.assertLess(time.monotonic() - started, 1)
            with scope_locks(self.other, [self.user], timeout=0):
                pass

    def test_sql_effect_and_guard_loss_never_reconnect(self):
        with self.connection.cursor() as cursor:
            cursor.execute("CREATE TABLE cf_guard_probe(id INT PRIMARY KEY) ENGINE=InnoDB")
        with self.assertRaises(ContractError) as caught:
            with scope_locks(self.connection, [self.user], timeout=0):
                self.connection.begin()
                with self.connection.cursor() as cursor:
                    cursor.execute("INSERT INTO cf_guard_probe VALUES(1)")
                    cursor.execute("SELECT CONNECTION_ID()")
                    owner = cursor.fetchone()[0]
                with self.admin.cursor() as cursor:
                    cursor.execute("KILL CONNECTION " + str(int(owner)))
                self.connection.commit()
        self.assertEqual(caught.exception.code, "AUTHORITY_UNAVAILABLE")
        with self.other.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_guard_probe")
            self.assertEqual(cursor.fetchone()[0], 0)
        with scope_locks(self.other, [self.user], timeout=5):
            pass

    def test_invalid_scopes_fail_before_any_sql_effect(self):
        for scopes in ([], [{}], [{**self.user, "extra": "x"}], [{**self.user, "type": "resource"}]):
            with self.assertRaises((ValueError, ContractError)):
                with scope_locks(self.connection, scopes, timeout=0):
                    self.fail("invalid scope accepted")
