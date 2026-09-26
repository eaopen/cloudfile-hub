from pathlib import Path
import tempfile

from cloudfile_extensions.common.errors import ContractError
from cloudfile_extensions.events.export import AuditCSV
from cloudfile_extensions.events.export_job import AuditExportJob
from cloudfile_extensions.events.export_results import AuditExportResults
from cloudfile_extensions.events.query import AuditReader
from cloudfile_extensions.jobs.store import JobStore
from cloudfile_extensions.jobs.worker import Handler, JobWorker
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AuditExportResultTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.directory = tempfile.TemporaryDirectory()
        self.root = self.directory.name
        self.store = JobStore(self.connection)
        self.repo = "11111111-1111-4111-8111-111111111111"
        with self.connection.cursor() as sql:
            sql.execute("INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at,source_path) "
                        "VALUES(%s,'file','','update','writer','hub','succeeded','2026-09-10','/private')", (self.repo,))
        self.reader = AuditReader(self.connection, secret=b"test-only-signing-key-with-32-bytes!", authorize=lambda *args: True)
        self.exporter = AuditCSV(self.reader, authorize_export=lambda *args: True, redact=lambda actor, row: row)
        self.job = self.store.submit(actor="owner", actor_kind="user", kind="audit.export",
            scope={"type": "repo", "provider": "cloudfile", "external_id": self.repo},
            request={"start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"},
            idempotency_key="export-1")[0]
        JobWorker(self.store, owner="worker", handlers={"audit.export": Handler(
            AuditExportJob(self.exporter, result_root=self.root))}).run_once()
        self.results = AuditExportResults(self.store, self.exporter, result_root=self.root)
        self.file = Path(self.root) / (self.job + ".1.csv")

    def tearDown(self):
        self.directory.cleanup()
        super().tearDown()

    def test_real_result_replays_current_visibility_with_fixed_cutoff(self):
        proof = self.results.verify(self.job, actor="owner")
        self.assertEqual(proof.size, self.file.stat().st_size)
        self.assertEqual(proof.result_ref, self.store.get(self.job)["result_ref"])
        with self.connection.cursor() as sql:
            sql.execute("INSERT INTO cf_audit_event(repo_id,object_type,object_id,operation,operator,source,result,occurred_at) "
                        "VALUES(%s,'file','','update','new','hub','succeeded','2026-09-11')", (self.repo,))
        self.assertEqual(self.results.verify(self.job, actor="owner"), proof)

    def test_row_revocation_or_redaction_change_requires_new_export(self):
        self.reader.authorize = lambda actor, event: event.get("source_path") != "/private"
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="owner")
        self.assertEqual(caught.exception.code, "EXPORT_REGENERATE")
        self.reader.authorize = lambda *args: True
        self.exporter.redact = lambda actor, row: {**row, "operator": "[redacted]"}
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="owner")
        self.assertEqual(caught.exception.code, "EXPORT_REGENERATE")

    def test_owner_scope_expiry_and_nonready_results_rejected(self):
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="other")
        self.assertEqual(caught.exception.status, 404)
        self.exporter.authorize = lambda *args: False
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="owner")
        self.assertEqual(caught.exception.status, 403)
        self.exporter.authorize = lambda *args: True
        expires = self.store.get(self.job)["checkpoint"]["expires_at"]
        self.results.clock = lambda: expires + 1
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="owner")
        self.assertEqual(caught.exception.code, "EXPORT_UNAVAILABLE")
        with self.connection.cursor() as sql:
            sql.execute("UPDATE cf_background_job SET status='failed' WHERE job_id=%s", (self.job,))
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="owner")
        self.assertEqual(caught.exception.code, "EXPORT_NOT_READY")

    def test_expiry_during_regeneration_never_releases_content(self):
        expires = self.store.get(self.job)["checkpoint"]["expires_at"]
        readings = iter((expires - 1, expires - 1, expires))
        self.results.clock = lambda: next(readings)
        with self.assertRaises(ContractError) as caught:
            self.results.read(self.job, actor="owner")
        self.assertEqual(caught.exception.code, "EXPORT_UNAVAILABLE")

    def test_tampered_and_symlink_files_are_never_verified(self):
        original = self.file.read_bytes()
        self.file.write_bytes(original.replace(b"writer", b"reader"))
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="owner")
        self.assertEqual(caught.exception.code, "EXPORT_UNAVAILABLE")
        target = Path(self.root) / "separate.csv"
        self.file.rename(target)
        self.file.symlink_to(target)
        with self.assertRaises(ContractError) as caught:
            self.results.verify(self.job, actor="owner")
        self.assertEqual(caught.exception.code, "EXPORT_UNAVAILABLE")
