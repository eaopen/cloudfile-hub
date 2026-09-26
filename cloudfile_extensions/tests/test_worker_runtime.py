"""Worker polling/shutdown and startup fail-closed boundaries."""

import contextlib
import io
import threading
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from cloudfile_extensions.jobs.runtime import configured_handlers, main, run_loop


class WorkerRuntimeTests(unittest.TestCase):
    def test_idle_wait_is_bounded_and_shutdown_wakes_it(self):
        stop = Mock()
        stop.is_set.side_effect = [False, True]
        worker = Mock()
        worker.run_once.return_value = None
        emitted = []
        self.assertEqual(run_loop(worker, stop, poll_seconds=3, emit=emitted.append), 0)
        stop.wait.assert_called_once_with(3)
        self.assertEqual(emitted, [{"state": "ready"}, {"state": "stopped"}])

    def test_once_processes_one_attempt_without_idle_sleep(self):
        stop = Mock()
        stop.is_set.return_value = False
        worker = Mock()
        worker.run_once.return_value = "job-id"
        emitted = []
        self.assertEqual(run_loop(worker, stop, once=True, emit=emitted.append), 1)
        worker.run_once.assert_called_once()
        stop.wait.assert_not_called()
        self.assertEqual(emitted[1], {"state": "job_processed", "job_id": "job-id"})

    def test_stop_finishes_current_handler_but_claims_no_more_work(self):
        stop = threading.Event()
        worker = Mock()
        def execute():
            stop.set()
            return "completed-attempt"
        worker.run_once.side_effect = execute
        self.assertEqual(run_loop(worker, stop), 1)
        worker.run_once.assert_called_once()

    def test_database_fault_is_not_retried_inside_same_worker(self):
        worker = Mock()
        worker.run_once.side_effect = RuntimeError("sensitive DB detail")
        with self.assertRaises(RuntimeError):
            run_loop(worker, threading.Event())
        worker.run_once.assert_called_once()

    def test_registry_rejects_duplicate_or_request_selected_configuration(self):
        for sources in ('{}', '[]', '{"one":"/first","one":"/second"}',
                        '{"one":"relative"}', '{"module":"module.handler"}'):
            with self.assertRaises(ValueError):
                configured_handlers({"CLOUDFILE_IMPORT_SOURCES": sources,
                                     "CLOUDFILE_IMPORT_REPORT_ROOT": "/registered/reports"})
        handlers = configured_handlers({"CLOUDFILE_IMPORT_SOURCES": '{"one":"/registered/source"}',
                                        "CLOUDFILE_IMPORT_REPORT_ROOT": "/registered/reports"})
        self.assertEqual(set(handlers), {"migration.scan"})
        self.assertIsNone(handlers["migration.scan"].barrier_guard)

    def test_startup_schema_failure_closes_connection_without_claim_or_ddl(self):
        connection = Mock()
        output = io.StringIO()
        with patch("cloudfile_extensions.jobs.runtime.configured_handlers", return_value={}), \
                patch("cloudfile_extensions.jobs.runtime.connect_database", return_value=connection), \
                patch("cloudfile_extensions.jobs.runtime.SchemaRunner") as schema, \
                patch("cloudfile_extensions.jobs.runtime.JobStore") as store, \
                contextlib.redirect_stderr(output):
            schema.return_value.require_current.side_effect = RuntimeError("password=secret")
            self.assertEqual(main(["--once"]), 1)
            schema.return_value.apply.assert_not_called()
            store.assert_not_called()
        connection.close.assert_called_once()
        self.assertNotIn("secret", output.getvalue())

    def test_staging_requires_explicit_separate_registered_work_volume(self):
        environment = dict(CLOUDFILE_IMPORT_SOURCES='{"one":"/registered/source"}',
            CLOUDFILE_IMPORT_REPORT_ROOT="/registered/reports", CLOUDFILE_IMPORT_WORK_ROOT="/registered/work")
        handlers = configured_handlers(environment)
        self.assertEqual(set(handlers), {"migration.scan", "migration.stage", "migration.verify-copy"})
        self.assertNotIn("migration.import", handlers)
        for root in ("", "relative", "/registered/source", "/registered/source/work", "/registered"):
            with self.assertRaises(ValueError):
                configured_handlers(dict(environment, CLOUDFILE_IMPORT_WORK_ROOT=root))

    def test_invalid_limits_fail_before_configuration_or_connection(self):
        with patch("cloudfile_extensions.jobs.runtime.connect_database") as connect, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--poll-seconds", "0"]), 1)
            self.assertEqual(main(["--lease-seconds", "301"]), 1)
            connect.assert_not_called()

    def test_source_and_report_overlap_including_parent_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            source.mkdir()
            alias = Path(root) / "alias"
            alias.symlink_to(source, target_is_directory=True)
            for report in (source, source / "reports", Path(root), alias / "reports"):
                with self.assertRaises(ValueError):
                    configured_handlers({"CLOUDFILE_IMPORT_SOURCES": '{"one":"' + str(source) + '"}',
                                         "CLOUDFILE_IMPORT_REPORT_ROOT": str(report)})
