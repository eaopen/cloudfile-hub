"""Actual isolated SQL intake with explicit verified-notification fixture.

Signature verification is covered separately; these cases prove no session
deletion and are not a substitute for the end-to-end backchannel workflow.
"""
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch
import json

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.identity.logout_jobs import BackchannelJobs
from cloudfile_extensions.identity.logout_token import LogoutNotification, LogoutTokenValidator
from cloudfile_extensions.jobs.store import JobStore
from cloudfile_extensions.jobs.worker import Execution
from cloudfile_extensions.identity.logout_worker import BackchannelWorker
from cloudfile_extensions.identity.session_delete import NativeDBSessionDelete
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class BackchannelIntakeTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.validator = Mock(spec=LogoutTokenValidator)
        self.validator.config = SimpleNamespace(issuer="https://idp.invalid/", client_id="cloudfile")
        # ``clock`` is an instance-owned dependency set by the validator's
        # constructor, not a class member included by Mock(spec=...).
        self.validator.clock = Mock(return_value=1000)
        self.notification = LogoutNotification("https://idp.invalid/", "cloudfile", "logout-jti-1",
            "opaque-subject", "opaque-session", 1000, 1060)
        self.validator.validate.return_value = self.notification
        self.intake = BackchannelJobs(JobStore(self.connection), self.validator)

    def test_replay_one_durable_job_and_never_store_jwt(self):
        first, created = self.intake.submit("private-jwt-fixture")
        self.assertTrue(created)
        second, created = self.intake.submit("private-jwt-fixture")
        self.assertEqual(first, second)
        self.assertFalse(created)
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT request_json,actor,actor_kind,barrier_active FROM cf_background_job WHERE job_id=%s", (first,))
            request, actor, kind, barrier = cursor.fetchone()
            self.assertNotIn("private-jwt-fixture", request)
            self.assertEqual((actor, kind, barrier), (self.intake.actor, "service", 0))

    def test_same_jti_cannot_change_logout_target(self):
        self.intake.submit("fixture")
        self.validator.validate.return_value = replace(self.notification, session_id="different-session")
        with self.assertRaises(ContractError) as caught:
            self.intake.submit("changed-fixture")
        self.assertEqual(caught.exception.code, "IDEMPOTENCY_CONFLICT")

    def test_worker_page_fact_uses_valid_result_in_actual_sql_transaction(self):
        # Session deletion itself is an explicit fixture, not a native E2E proof.
        job_id, _ = self.intake.submit("fixture")
        store = self.intake.store
        claim = store.claim("logout-worker", kinds=(self.intake.KIND,), lease_seconds=300)
        deletion = Mock(spec=NativeDBSessionDelete)
        deletion.index = self.intake.index
        deletion.delete.return_value = 1
        with patch.object(self.intake.index, "targets", side_effect=[["session-reference"], []]):
            BackchannelWorker(self.intake, deletion).execute(Execution(store, claim, 300))
        deletion.delete.assert_called_once()
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT payload,resource_state,search_state FROM cf_event_outbox")
            rows = [row for row in cursor.fetchall() if json.loads(row[0])["action"] == "identity.logout.sessions"]
            self.assertEqual(len(rows), 1)
            payload = json.loads(rows[0][0])
            self.assertEqual(payload["result"], "succeeded")
            self.assertEqual(payload["job_id"], job_id)
            self.assertEqual(rows[0][1:], ("done", "done"))

    def test_expired_during_locking_rejected_for_insert_and_replay(self):
        self.validator.clock.return_value = 1060
        with self.assertRaises(ContractError):
            self.intake.submit("fixture")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM cf_background_job")
            self.assertEqual(cursor.fetchone(), (0,))
        self.validator.clock.return_value = 1000
        self.intake.submit("fixture")
        self.validator.clock.return_value = 1060
        with self.assertRaises(ContractError) as caught:
            self.intake.submit("fixture")
        self.assertEqual(caught.exception.status, 401)
