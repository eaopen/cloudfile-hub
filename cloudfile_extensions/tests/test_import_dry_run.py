"""Real SQL worker/dry-run integration, isolated report/source temporary volumes."""
import json
import importlib.util
import os
import subprocess
import selectors
import sys
import unittest
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

    def native_worker_environment(self, source, reports):
        return {**os.environ, "CLOUDFILE_DB_HOST": self.options["host"],
                       "CLOUDFILE_DB_PORT": str(self.options["port"]), "CLOUDFILE_DB_USER": "root",
                       "CLOUDFILE_DB_PASSWORD": "", "CLOUDFILE_DB_NAME": self.database,
                       "CLOUDFILE_IMPORT_SOURCES": json.dumps({"registered": source}),
                       "CLOUDFILE_IMPORT_REPORT_ROOT": reports}

    def run_native_worker(self, source, reports):
        return subprocess.run([sys.executable, "-m", "cloudfile_extensions.jobs", "--once"],
                              env=self.native_worker_environment(source, reports),
                              capture_output=True, text=True, timeout=30)

    @unittest.skipUnless(importlib.util.find_spec("MySQLdb"), "requires CE mysqlclient runtime")
    def test_native_cli_claims_and_completes_real_scan(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as reports:
            (Path(source) / "drawing.prt").write_bytes(b"drawing")
            job_id = self.submit({"source_id": "registered"})
            result = self.run_native_worker(source, reports)
            self.assertEqual(result.returncode, 0, result.stderr)
            messages = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(messages, [{"state": "ready"}, {"state": "job_processed", "job_id": job_id},
                                        {"state": "stopped"}])
            self.assertEqual(self.store.get(job_id)["status"], "succeeded")
            self.assertEqual(len(list(Path(reports).iterdir())), 1)

    @unittest.skipUnless(importlib.util.find_spec("MySQLdb"), "requires CE mysqlclient runtime")
    def test_native_cli_refuses_schema_drift_without_claiming_or_upgrading(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as reports:
            job_id = self.submit({"source_id": "registered"})
            with self.connection.cursor() as cursor:
                cursor.execute("UPDATE cf_schema_migration SET checksum=%s", ("0" * 64,))
            result = self.run_native_worker(source, reports)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertEqual(self.store.get(job_id)["status"], "queued")
            self.assertEqual(list(Path(reports).iterdir()), [])

    @unittest.skipUnless(importlib.util.find_spec("MySQLdb"), "requires CE mysqlclient runtime")
    def test_native_cli_sigterm_wakes_idle_poll_and_closes_process(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as reports:
            process = subprocess.Popen([sys.executable, "-m", "cloudfile_extensions.jobs", "--poll-seconds", "30"],
                                       env=self.native_worker_environment(source, reports),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=15), "Worker startup timed out")
                self.assertEqual(json.loads(process.stdout.readline()), {"state": "ready"})
                process.terminate()
                output, errors = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, errors)
                self.assertEqual(json.loads(output), {"state": "stopped"})
                self.assertEqual(list(Path(reports).iterdir()), [])
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
