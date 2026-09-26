"""Real SQL job recovery; coordinator proofs here are not Server integration."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.jobs.store import BarrierProof, JobStore
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class JobStoreTest(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = JobStore(self.connection)
        self.scope = {"type": "user", "provider": "directory", "external_id": "u1"}

    def submit(self, **changes):
        return self.store.submit(**{**dict(actor="etech", actor_kind="service", kind="authorization.refresh",
                                           scope=self.scope, request={"refresh_subject": True},
                                           idempotency_key="request-1", barrier=True), **changes})

    def test_durable_idempotency_and_distinct_scope_encoding(self):
        job_id, created = self.submit()
        self.assertTrue(created)
        self.assertEqual(self.submit(), (job_id, False))
        self.assertTrue(self.store.active_barrier(self.scope))
        with self.assertRaises(ContractError) as caught:
            self.submit(request={"refresh_subject": False})
        self.assertEqual(caught.exception.status, 409)
        one = {"type": "subject", "provider": "a:b", "namespace": "c", "external_id": "d"}
        two = {"type": "subject", "provider": "a", "namespace": "b:c", "external_id": "d"}
        self.submit(scope=one, idempotency_key="other")
        self.assertTrue(self.store.active_barrier(one))
        self.assertFalse(self.store.active_barrier(two))

    def test_failed_and_cancelled_jobs_keep_barrier_until_verified_recovery(self):
        job_id, _ = self.submit()
        claim = self.store.claim("worker-1", kinds=("authorization.refresh",))
        self.store.fail(claim, code="DIRECTORY_UNAVAILABLE")
        self.assertTrue(self.store.active_barrier(self.scope))
        self.assertEqual(self.store.cancel(job_id, actor="admin", actor_kind="user")["status"], "cancelled")
        self.assertTrue(self.store.active_barrier(self.scope))
        self.store.retry(job_id, actor="admin", actor_kind="user")
        claim = self.store.claim("worker-2", kinds=("authorization.refresh",))
        with self.assertRaises(ContractError):
            self.store.complete(claim)

        @contextmanager
        def coordinator_fixture(claim):
            yield BarrierProof(claim.job_id, claim.epoch)

        self.store.complete(claim, barrier_guard=coordinator_fixture)
        self.assertFalse(self.store.active_barrier(self.scope))
        self.assertEqual(self.store.get(job_id)["status"], "succeeded")

    def test_expired_worker_cannot_publish_checkpoint_failure_or_completion(self):
        job_id, _ = self.submit(barrier=False)
        old = self.store.claim("old-worker", kinds=("authorization.refresh",))
        with self.connection.cursor() as cursor:
            cursor.execute("UPDATE cf_background_job SET lease_expiry=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) WHERE job_id=%s", (job_id,))
        new = self.store.claim("new-worker", kinds=("authorization.refresh",))
        self.assertEqual(new.epoch, old.epoch + 1)
        for action in (lambda: self.store.checkpoint(old, step="projecting", checkpoint={}),
                       lambda: self.store.fail(old, code="FAILED"), lambda: self.store.complete(old)):
            with self.assertRaises(ContractError) as caught:
                action()
            self.assertEqual(caught.exception.code, "WORKER_LEASE_LOST")
        self.store.checkpoint(new, step="reconciling", checkpoint={"epoch": "new-context"})
        self.store.complete(new)
        self.assertEqual(self.store.get(job_id)["status"], "succeeded")

    def test_concurrent_workers_only_claim_job_once(self):
        import pymysql
        self.submit()
        rendezvous = Barrier(2)

        def claim(owner):
            connection = pymysql.connect(**self.options, database=self.database)
            try:
                rendezvous.wait(timeout=5)
                return JobStore(connection).claim(owner, kinds=("authorization.refresh",))
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(executor.map(claim, ("worker-1", "worker-2")))
        self.assertEqual(sum(value is not None for value in claims), 1)
