from contextlib import contextmanager
import tempfile

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.export import AuditCSV
from cloudfile_extensions.events.export_job import AuditExportJob
from cloudfile_extensions.events.query import AuditReader
from cloudfile_extensions.events.service import AuditService
from cloudfile_extensions.jobs.store import JobStore
from cloudfile_extensions.jobs.worker import Handler, JobWorker
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AuditServiceTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.jobs = JobStore(self.connection)
        self.allowed, self.entered = True, []
        @contextmanager
        def guard(actor, repo):
            self.entered.append((actor, repo))
            if not self.allowed:
                raise ContractError("FORBIDDEN", "Audit export scope is not available", 403)
            yield
        self.reader = AuditReader(self.connection, secret=b"test-only-signing-key-with-32-bytes!", authorize=lambda *args: True)
        def redact(actor, row):
            return {**row, "operator": "[redacted]", "raw_payload": "do-not-return"}
        self.service = AuditService(self.reader, self.jobs, export_guard=guard, redact=redact)
        self.request = {"repo_id": "11111111-1111-4111-8111-111111111111",
                        "start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"}

    def create(self, **changes):
        return self.service.create_export(actor="employee", request={**self.request, **changes}, idempotency_key="export-1")

    def test_submit_idempotency_and_status_dto_do_not_expose_internals(self):
        job, created = self.create()
        self.assertTrue(created)
        self.assertIsNone(job["result_url"])
        self.assertEqual(self.create(), (job, False))
        self.assertEqual(set(job), {"job_id", "repo_id", "status", "step", "status_url", "result_url", "expires_at", "error_code"})
        self.assertEqual(self.service.export_status(job["job_id"], actor="employee"), job)
        with self.assertRaises(ContractError):
            self.create(action="file.updated")

    def test_unknown_body_fields_and_revocation_prevent_submission(self):
        for field in ("actor", "result_root", "upper_bound", "cursor", "max_rows"):
            with self.assertRaises(ContractError):
                self.create(**{field: "forged"})
        self.assertEqual(self.entered, [])
        self.allowed = False
        with self.assertRaises(ContractError):
            self.create()
        with self.connection.cursor() as sql:
            sql.execute("SELECT COUNT(*) FROM cf_background_job")
            self.assertEqual(sql.fetchone()[0], 0)

    def test_other_users_cannot_inspect_or_cancel_and_current_scope_is_checked(self):
        job, _ = self.create()
        for method in (self.service.export_status, self.service.cancel_export):
            with self.assertRaises(ContractError) as caught:
                method(job["job_id"], actor="other")
            self.assertEqual(caught.exception.status, 404)
        self.allowed = False
        with self.assertRaises(ContractError):
            self.service.cancel_export(job["job_id"], actor="employee")
        self.assertEqual(self.jobs.get(job["job_id"])["status"], "queued")
        self.allowed = True
        self.assertEqual(self.service.cancel_export(job["job_id"], actor="employee")["status"], "cancelled")

    def test_successful_worker_is_projected_to_public_result_url(self):
        job, _ = self.create()
        exporter = AuditCSV(self.reader, authorize_export=lambda *args: True, redact=lambda actor, row: row)
        with tempfile.TemporaryDirectory() as root:
            JobWorker(self.jobs, owner="worker", handlers={"audit.export": Handler(
                AuditExportJob(exporter, result_root=root))}).run_once()
            public = self.service.export_status(job["job_id"], actor="employee")
            self.assertEqual(public["status"], "succeeded")
            self.assertEqual(public["result_url"], public["status_url"] + "result/")
            self.assertTrue(public["expires_at"].endswith("Z"))
            self.assertNotIn("audit-export:", str(public))

    def test_event_response_is_redacted_and_has_no_extra_fields(self):
        with self.connection.cursor() as sql:
            sql.execute("INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at) "
                        "VALUES(%s,'file','','update','private@example.invalid','api','success','2026-09-10')", (self.request["repo_id"],))
        self.create()
        page = self.service.events(actor="employee", filters=self.request)
        self.assertTrue(page["items"])
        for event in page["items"]:
            self.assertEqual(set(event), set(AuditReader.FIELDS))
            self.assertEqual(event["operator"], "[redacted]")
        self.service.redact = lambda actor, row: {**row, "actor_user_id": "guessed"}
        with self.assertRaises(ContractError) as caught:
            self.service.events(actor="employee", filters=self.request)
        self.assertEqual(caught.exception.status, 503)

    def test_actual_database_failure_is_sanitized(self):
        job, _ = self.create()
        with self.connection.cursor() as sql:
            sql.execute("DROP TABLE cf_background_job")
        with self.assertRaises(ContractError) as caught:
            self.service.export_status(job["job_id"], actor="employee")
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn(self.database, caught.exception.message)
