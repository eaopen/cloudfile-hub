"""Real SQL worker/dry-run integration, isolated report/source temporary volumes."""
import json
from pathlib import Path
import tempfile

from cloudfile_extensions.jobs.store import JobStore
from cloudfile_extensions.jobs.worker import Handler, JobWorker
from cloudfile_extensions.migration.dry_run import ImportDryRun
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class ImportDryRunTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = JobStore(self.connection)

    def submit(self, request):
        return self.store.submit(actor="admin", actor_kind="user", kind="migration.scan",
            scope={"type": "repo", "provider": "directory", "external_id": "00000000-0000-0000-0000-000000000001"},
            request=request, idempotency_key="dry-run", barrier=False)[0]

    def test_dry_run_streams_report_and_aggregates_without_target_writes(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as reports:
            root = Path(source).resolve()
            (root / "empty").mkdir()
            (root / "drawing.prt").write_bytes(b"drawing")
            job_id = self.submit({"source_id": "registered", "content_hash": True})
            handler = ImportDryRun(sources={"registered": str(root)}, report_root=str(Path(reports).resolve()))
            JobWorker(self.store, owner="import-worker", handlers={"migration.scan": Handler(handler)}).run_once()
            state = self.store.get(job_id)
            self.assertEqual(state["status"], "succeeded")
            self.assertEqual(state["checkpoint"]["files"], 1)
            self.assertEqual(state["checkpoint"]["bytes"], 7)
            self.assertFalse(state["checkpoint"]["source_snapshot_verified"])
            report = Path(reports) / state["result_ref"].split(":", 1)[1]
            rows = [json.loads(line) for line in report.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual((root / "drawing.prt").read_bytes(), b"drawing")

    def test_symlink_failure_preserves_report_but_never_marks_success(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as reports:
            root = Path(source).resolve()
            (root / "link").symlink_to(root, target_is_directory=True)
            job_id = self.submit({"source_id": "registered"})
            handler = ImportDryRun(sources={"registered": str(root)}, report_root=str(Path(reports).resolve()))
            JobWorker(self.store, owner="import-worker", handlers={"migration.scan": Handler(handler)}).run_once()
            state = self.store.get(job_id)
            self.assertEqual(state["status"], "failed")
            self.assertEqual(state["error_code"], "SOURCE_SCAN_INCOMPLETE")
            self.assertEqual(state["checkpoint"]["errors"], 1)
            self.assertEqual(len(list(Path(reports).iterdir())), 1)

    def test_arbitrary_server_path_is_not_accepted_as_source_id(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as reports:
            job_id = self.submit({"source_id": source})
            handler = ImportDryRun(sources={"registered": source}, report_root=reports)
            JobWorker(self.store, owner="import-worker", handlers={"migration.scan": Handler(handler)}).run_once()
            self.assertEqual(self.store.get(job_id)["status"], "failed")
            self.assertEqual(list(Path(reports).iterdir()), [])
