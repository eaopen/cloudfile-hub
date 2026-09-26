from pathlib import Path
import tempfile
from unittest.mock import Mock

from cloudfile_extensions.events.export import AuditCSV
from cloudfile_extensions.events.export_job import AuditExportJob
from cloudfile_extensions.events.query import AuditReader
from cloudfile_extensions.jobs.store import JobStore
from cloudfile_extensions.jobs.worker import Handler, JobWorker
from cloudfile_extensions.schema.runner import SchemaRunner
from cloudfile_extensions.tests.test_schema import DatabaseTestCase


class AuditExportJobTests(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        SchemaRunner(self.connection).apply()
        self.store = JobStore(self.connection)
        self.repo = "11111111-1111-4111-8111-111111111111"
        self.request = {"start": "2026-09-01T00:00:00Z", "end": "2026-10-01T00:00:00Z"}
        self.visible = True
        reader = AuditReader(self.connection, secret=b"test-only-signing-key-with-32-bytes!",
                             authorize=lambda actor, event: self.visible)
        self.exporter = AuditCSV(reader, authorize_export=lambda actor, repo: self.visible,
                                 redact=lambda actor, row: row)

    def submit(self, request=None):
        return self.store.submit(actor="employee", actor_kind="user", kind="audit.export",
            scope={"type": "repo", "provider": "cloudfile", "external_id": self.repo},
            request=self.request if request is None else request, idempotency_key="export-1")[0]

    def test_actual_worker_publishes_private_file_and_durable_result(self):
        job = self.submit()
        with tempfile.TemporaryDirectory() as root:
            handler = AuditExportJob(self.exporter, result_root=root)
            worker = JobWorker(self.store, owner="worker", handlers={"audit.export": Handler(handler)})
            self.assertEqual(worker.run_once(), job)
            current = self.store.get(job)
            self.assertEqual(current["status"], "succeeded")
            name = current["result_ref"].removeprefix("audit-export:")
            self.assertEqual(list(Path(root).iterdir()), [Path(root) / name])
            self.assertEqual((Path(root) / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(current["checkpoint"]["bytes"], (Path(root) / name).stat().st_size)
            self.assertTrue((Path(root) / name).read_bytes().startswith(b'"id"'))

    def test_revoked_export_fails_without_artifact(self):
        job = self.submit()
        self.visible = False
        with tempfile.TemporaryDirectory() as root:
            worker = JobWorker(self.store, owner="worker", handlers={"audit.export": Handler(
                AuditExportJob(self.exporter, result_root=root))})
            worker.run_once()
            self.assertEqual(self.store.get(job)["error_code"], "FORBIDDEN")
            self.assertIsNone(self.store.get(job)["result_ref"])
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_partial_output_failure_is_removed_and_request_cannot_select_path(self):
        job = self.submit()
        def fail(**query):
            yield b"partial sensitive content"
            raise RuntimeError("private credential")
        exporter = Mock()
        exporter.generate.side_effect = fail
        with tempfile.TemporaryDirectory() as root:
            worker = JobWorker(self.store, owner="worker", handlers={"audit.export": Handler(
                AuditExportJob(exporter, result_root=root))})
            worker.run_once()
            current = self.store.get(job)
            self.assertEqual(current["error_code"], "JOB_HANDLER_FAILED")
            self.assertIsNone(current["result_ref"])
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_unknown_request_fields_rejected_before_creating_file(self):
        job = self.submit({**self.request, "result_root": "/requested/path"})
        with tempfile.TemporaryDirectory() as root:
            worker = JobWorker(self.store, owner="worker", handlers={"audit.export": Handler(
                AuditExportJob(self.exporter, result_root=root))})
            worker.run_once()
            self.assertEqual(self.store.get(job)["error_code"], "INVALID_REQUEST")
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_cancellation_after_file_link_removes_own_artifact(self):
        job = self.submit()
        with tempfile.TemporaryDirectory() as root:
            handler = AuditExportJob(self.exporter, result_root=root)
            def execute(execution):
                checkpoint = execution.checkpoint
                def cancel_before_ready(*, step, value):
                    if step == "export-ready":
                        self.store.cancel(job, actor="employee", actor_kind="user")
                    checkpoint(step=step, value=value)
                execution.checkpoint = cancel_before_ready
                return handler(execution)
            worker = JobWorker(self.store, owner="worker", handlers={"audit.export": Handler(execute)})
            worker.run_once()
            current = self.store.get(job)
            self.assertEqual(current["status"], "cancelled")
            self.assertIsNone(current["result_ref"])
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_preexisting_destination_is_preserved(self):
        job = self.submit()
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / (job + ".1.csv")
            destination.write_bytes(b"preexisting artifact")
            worker = JobWorker(self.store, owner="worker", handlers={"audit.export": Handler(
                AuditExportJob(self.exporter, result_root=root))})
            worker.run_once()
            self.assertEqual(self.store.get(job)["status"], "failed")
            self.assertIsNone(self.store.get(job)["result_ref"])
            self.assertEqual(destination.read_bytes(), b"preexisting artifact")
            self.assertEqual(list(Path(root).iterdir()), [destination])
