"""Isolated SQL lease state tests; not proof of actual native write fencing."""
from contextlib import contextmanager

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.locks.store import LockLeaseStore
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class LockLeaseTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = LockLeaseStore()
        self.args = dict(resource_uid="11111111-1111-4111-8111-111111111111",
            repo_id="22222222-2222-4222-8222-222222222222", actor="employee", holder="session-one", token="a" * 64)

    @contextmanager
    def transaction(self):
        self.connection.begin()
        try:
            with self.connection.cursor() as sql:
                yield sql
            self.connection.commit()
        finally:
            self.connection.rollback()

    def acquire(self, sql, **changes):
        return self.store.acquire(sql, **{**self.args, "base_version": "b" * 40, **changes})

    def test_replay_release_reacquire_preserves_monotonic_fencing(self):
        with self.transaction() as sql:
            first = self.acquire(sql)
            self.assertEqual(self.acquire(sql), first)
            released = self.store.change(sql, **self.args, fencing=1, release=True)
            self.assertFalse(released["active"])
            self.assertEqual(released["fencing"], "1")
            again = self.acquire(sql, token="c" * 64)
            self.assertEqual(again["fencing"], "2")
            with self.assertRaises(ContractError):
                self.store.change(sql, **self.args, fencing=1)
            sql.execute("SELECT token_digest FROM cf_lock_lease WHERE resource_uid=%s", (self.args["resource_uid"],))
            self.assertNotEqual(sql.fetchone()[0], "c" * 64)

    def test_same_employee_different_session_cannot_bypass_lease(self):
        with self.transaction() as sql:
            self.acquire(sql)
            with self.assertRaises(ContractError) as caught:
                self.acquire(sql, holder="session-two")
            self.assertEqual(caught.exception.status, 423)
            with self.assertRaises(ContractError):
                self.store.change(sql, **{**self.args, "token": "c" * 64}, fencing=1)

    def test_expired_lease_cannot_renew_and_new_acquisition_increments(self):
        with self.transaction() as sql:
            self.acquire(sql)
            sql.execute("UPDATE cf_lock_lease SET expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) WHERE resource_uid=%s", (self.args["resource_uid"],))
            with self.assertRaises(ContractError):
                self.store.change(sql, **self.args, fencing=1)
            self.assertEqual(self.acquire(sql, holder="session-two")["fencing"], "2")

    def test_conditional_management_release_increments_without_reset(self):
        with self.transaction() as sql:
            self.acquire(sql)
            key = {name: self.args[name] for name in ("resource_uid", "repo_id")}
            with self.assertRaises(ContractError):
                self.store.force_release(sql, **key, fencing=2)
            result = self.store.force_release(sql, **key, fencing=1)
            self.assertEqual(result["fencing"], "2")
            self.assertFalse(result["active"])
            self.assertEqual(self.acquire(sql)["fencing"], "3")
